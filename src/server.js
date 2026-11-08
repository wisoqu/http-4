// ─────────────────────────────────────────────────────────────────────────────
// H4 origin server (semantics layer, wire-agnostic).
//
// DESIGN RULE THAT DRIVES THIS FILE:
//   security checks are ordered by ascending cost, and every check that can be
//   answered "no" without touching the origin does so.
//
//   0. frame decode            ~100 ns   (bounds-checked, no allocation)
//   1. capability verify       ~4 µs     (HMAC chain; root sig cached by hash)
//   2. limit check             ~1-4 µs   (receipt HMAC or one integer)
//   3. cost prediction         ~200 ns   (table lookup + static estimate)
//   4. dedup / coalesce        ~1 µs     (map probe, can save 100% of the work)
//   5. handler                 expensive ← nothing hostile reaches here
//
// The wire adapter (QUIC in production, TCP/TLS here) only moves bytes; all
// policy lives here so it can be unit-tested without a network.
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import {
  F, REJECT, CLASS, MODE, CACHE,
  iterFrames, decodeHeadersFrame, decodeIntent, decodeCost, decodeCap,
  encodeResult, encodeRate, encodeReject, encodeHeadersFrame, encodeData, encodeCost,
} from './frames.js';
import { verify, KeyRegistry, verifyCache, CAPS } from './identity.js';
import { Limiter, poeChallenge, checkPoE, CLASS_WEIGHT } from './limits.js';
import { H4Cache } from './cache.js';

export class H4Server {
  constructor({
    routes = {},
    registry = new KeyRegistry(),
    limiter = new Limiter(),
    cache = new H4Cache(),
    accessLog = null,
    requireCap = false,
  } = {}) {
    this.routes = routes;
    this.registry = registry;
    this.limiter = limiter;
    this.cache = cache;
    this.accessLog = accessLog;
    this.requireCap = requireCap;
    this.verifyCache = verifyCache;
    this.metrics = {
      requests: 0, served: 0, rejected: 0, coalesced: 0, cacheHits: 0,
      capVerifies: 0, poeChecks: 0, costPredicted: 0, bytesIn: 0, bytesOut: 0,
      savedByCacheMs: 0, savedByCoalesceMs: 0,
    };
  }

  /**
   * Full request handling. Everything is synchronous except the handler, so
   * the reject path never yields the event loop (a yield under load is how a
   * "cheap" reject becomes an expensive one).
   */
  async handle(req, now = Date.now()) {
    this.metrics.requests++;

    // ── 0. structural validation ────────────────────────────────────────────
    const headers = req.headers ?? [];
    const h = Object.fromEntries(headers);
    const path = h[':path'] ?? '/';
    const method = (h[':method'] ?? 'GET').toUpperCase();
    const intent = req.intent ?? { mode: MODE.QUERY, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' };
    const cost = req.cost ?? { predicted: 0, costClass: CLASS.CHEAP, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 };
    const cap = req.cap ?? null;
    if (typeof path !== 'string' || path.length > 8192) return this._reject(REJECT.MALFORMED, 'bad path');

    // ── 1. identity (only if a token is present, or required) ───────────────
    let identity = null;
    if (cap && cap.token && cap.token.length) {
      this.metrics.capVerifies++;
      const v = verify(cap.token, this.registry, { now, cache: this.verifyCache, required: 0 });
      if (!v.ok) return this._reject(REJECT[v.code] ?? REJECT.CAP_INVALID, v.why);
      identity = v;
    } else if (this.requireCap) {
      return this._reject(REJECT.CAP_INVALID, 'capability required');
    }
    // ── limiting keys ───────────────────────────────────────────────────────
    // An agent is limited per (grant, instance) so that several agents sharing
    // one token each get a fair share; the *grant* is additionally limited in
    // aggregate so a shared or leaked token cannot be fanned out into a botnet.
    // Anonymous callers are limited per (claimed instance, address) plus an
    // aggregate per address to bound free identity churn.
    const instanceId = h['h4-agent-instance'] || '';
    const subject = identity
      ? crypto.createHash('sha256').update(`${identity.subject}|${instanceId}`).digest('hex').slice(0, 16)
      : this._subjectFromRequest(req, h);
    // Identified: aggregate key is the issuer grant (fan-out ceiling).
    // Anonymous: aggregate key is the network address (churn ceiling).
    const net = identity ? identity.grant : (req.peer ?? null);
    const netAllowance = identity
      ? this.limiter.budget * (1 + this.limiter.identityBonus) * Math.max(1, Math.min(identity.maxSubs || 1, 4096))
      : 0;

    // ── 2. limits (cooperative receipt → enforced bucket → priced effort) ───
    const rl = req.rate ?? null; // {receipt, mac} from h4-rl header
    const costClass = this._classify(path, method, intent, cost);
    const limit = this.limiter.check({
      subject, net, netAllowance, costClass,
      receipt: rl?.receipt, mac: rl?.mac, sessionKey: req.sessionKey ?? null,
      identityTrusted: !!identity,
    }, now);

    if (!limit.allow) {
      this.metrics.rejected++;
      if (limit.code === 'EFFORT_REQUIRED') {
        // Cheap: recompute a challenge; zero stored state. Attacker pays 2^d.
        this.metrics.poeChecks++;
        const ch = poeChallenge(subject, Math.floor(now / 30_000));
        const nonce = req.effortNonce;
        if (nonce !== undefined && checkPoE(ch, nonce, limit.difficulty)) {
          // Earned budget: let it through and do not re-price this window.
          this.limiter.entries.get(subject).spent -= CLASS_WEIGHT[costClass] * 4;
          return this.handle(req, now);
        }
        return {
          reject: { code: REJECT.EFFORT_REQUIRED, difficulty: limit.difficulty, retryAfterMs: 0, detail: ch.toString('base64url') },
          frames: [encodeReject(REJECT.EFFORT_REQUIRED, { difficulty: limit.difficulty, detail: ch.toString('base64url') })],
          rate: null, cost: 0,
        };
      }
      return {
        reject: { code: REJECT.RATE_LIMITED, retryAfterMs: limit.retryAfterMs, difficulty: 0, detail: '' },
        frames: [encodeReject(REJECT.RATE_LIMITED, { retryAfterMs: limit.retryAfterMs })],
        rate: encodeRate({
          pressure: limit.pressure, budgetRemaining: 0,
          refillPerSec: Math.floor(this.limiter.budget / (this.limiter.windowMs / 1000)),
          blockUntilMs: now + limit.retryAfterMs, penaltyMs: limit.retryAfterMs,
        }),
        cost: 0,
      };
    }

    // ── 3. scope / capability gate before any work ──────────────────────────
    if (identity) {
      const need = this._requiredCaps(path, method);
      if ((identity.caps & need) !== need) {
        return this._reject(REJECT.SCOPE_DENIED, 'insufficient scope');
      }
      if (identity.scope !== '/' && !(path + '/').startsWith(identity.scope)) {
        return this._reject(REJECT.SCOPE_DENIED, 'path outside token scope');
      }
    }

    // ── 4. cost gate: refuse before spending ────────────────────────────────
    const predicted = this._predictCost(path, method, intent, cost, h);
    this.metrics.costPredicted++;
    if (intent.costCeiling && predicted > intent.costCeiling) {
      return this._reject(REJECT.COST_REFUSED, `predicted ${predicted} > ceiling ${intent.costCeiling}`);
    }
    if (cost.tokenBudget && intent.maxShape && intent.maxShape > cost.tokenBudget) {
      return this._reject(REJECT.COST_REFUSED, 'shape exceeds token budget');
    }

    // ── 4b. provision the client with the exact quota we will enforce ───────
    // Cheap (2 varints) and it removes an entire class of misbehaviour: a client
    // that knows its ceiling stops before the ceiling, instead of discovering it
    // through rejections.
    const advertised = {
      budget: limit.budgetRemaining !== undefined ? limit.budgetRemaining : this.limiter.budget,
      windowMs: this.limiter.windowMs,
      refillPerSec: Math.floor(this.limiter.budget / (this.limiter.windowMs / 1000)),
      trusted: !!identity,
    };

    // ── 5. cache + coalescing ───────────────────────────────────────────────
    const cacheKey = this._cacheKey(h, method, intent, req.body);
    const useDedup = intent.dedup || method === 'GET';
    const started = process.hrtime.bigint();

    let payload, cacheState, tokens = 0, memoReuse = 0;
    const cached = method === 'GET' || intent.dedup ? this.cache.get(cacheKey, now) : null;
    if (cached) {
      payload = cached.value; cacheState = cached.stale ? CACHE.HIT_STALE : CACHE.HIT;
      this.metrics.cacheHits++;
      this.metrics.savedByCacheMs += cached.computeMs ?? 0;
    } else {
      const route = this.routes[`${method} ${path}`] ?? this.routes[path];
      if (!route) return this._reject(REJECT.MALFORMED, 'no route');

      const run = async () => {
        const t0 = process.hrtime.bigint();
        const out = await route({
          path, method, headers: h, body: req.body, intent, cost, identity,
          now, remainingMs: intent.deadlineMs,
        });
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        return { out, ms };
      };

      let res;
      if (useDedup) {
        res = await this.cache.coalesce(cacheKey, run);
        if (res.coalesced) {
          cacheState = CACHE.MEMO; this.metrics.coalesced++;
          this.metrics.savedByCoalesceMs += res.value.ms;
        } else cacheState = CACHE.MISS;
        if (!res.coalesced && res.value.out !== undefined) {
          const ttl = res.value.out.ttlMs ?? this.cache.defaultTtlMs;
          this.cache.set(cacheKey, res.value.out, { ttlMs: ttl, computeMs: res.value.ms, memo: res.coalesced });
        }
        payload = res.value.out;
      } else {
        const r = await run();
        payload = r.out; cacheState = CACHE.COMPUTED;
      }
      tokens = payload?.tokens ?? 0;
      memoReuse = payload?.memoReuse ?? 0;
    }

    const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
    const costActual = this._actualCost(payload, predicted, cacheState);

    // ── 6. response: RESULT + RATE + COST, always ───────────────────────────
    const head = [
      [':status', String(payload?.status ?? 200)],
      ['content-type', payload?.type ?? 'application/json'],
      ['h4-cache', cacheState === CACHE.HIT ? 'hit' : cacheState === CACHE.HIT_STALE ? 'stale' : cacheState === CACHE.MEMO ? 'memo' : 'miss'],
      ['h4-cost', String(costActual)],
      ['h4-predicted', String(predicted)],
    ];
    const headFrame = encodeHeadersFrame(head);
    const bodyBuf = Buffer.from(typeof payload?.body === 'string' ? payload.body : JSON.stringify(payload?.body ?? {}));
    const frames = [
      encodeResult({
        status: payload?.status ?? 200, costActual, cache: cacheState,
        tokens, memoReuse, wallMs: Math.round(wallMs),
        costAsym: actualOrZero(costActual) - predicted,
      }),
      encodeRate({
        pressure: limit.pressure, budgetRemaining: limit.budgetRemaining,
        refillPerSec: Math.floor(this.limiter.budget / (this.limiter.windowMs / 1000)),
        blockUntilMs: limit.blockUntilMs ?? 0, penaltyMs: 0,
      }),
      encodeCost({
        predicted, costClass, effortBits: 0, budgetRemaining: limit.budgetRemaining,
        value: cost.value, tokenBudget: tokens,
      }),
      headFrame,
      encodeData(bodyBuf),
    ];

    this.metrics.served++;
    this.metrics.bytesOut += frames.reduce((a, f) => a + f.length, 0);

    if (this.accessLog) {
      this.accessLog.push({
        t: now, method, path, subject, status: payload?.status ?? 200,
        cache: cacheState, costActual, predicted, wallMs: +wallMs.toFixed(3),
        tier: limit.tier.join('+'),
      });
    }

    return {
      result: { status: payload?.status ?? 200, costActual, cache: cacheState, tokens, wallMs },
      advertised,
      frames, rate: limit, cost: costActual,
    };
  }

  _reject(code, detail) {
    this.metrics.rejected++;
    return {
      reject: { code, detail, retryAfterMs: 0, difficulty: 0 },
      frames: [encodeReject(code, { detail })],
      rate: null, cost: 0,
    };
  }

  _subjectFromRequest(req, h) {
    // Pre-handshake / anonymous: identity is (agent-instance, coarse network).
    // Deliberately NOT the IP alone — hash+instance avoids one client's burst
    // poisoning a whole NAT/CGNAT pool (collateral damage control).
    const inst = h['h4-agent-instance'] || h['h4-agent'] || '';
    const net = req.peer ?? 'anon';
    return crypto.createHash('sha256').update(`${inst}|${net}`).digest('hex').slice(0, 16);
  }

  _classify(path, method, intent, cost) {
    if (cost?.costClass !== undefined && cost.costClass !== CLASS.CHEAP) return cost.costClass;
    if (method === 'GET' || method === 'HEAD' || method === 'SUB') return CLASS.CHEAP;
    if (intent.mode === MODE.MUTATE) return CLASS.EXPENSIVE;
    return CLASS.NORMAL;
  }

  _requiredCaps(path, method) {
    if (method === 'GET' || method === 'HEAD') return CAPS.READ;
    if (method === 'SUB') return CAPS.SUBSCRIBE | CAPS.READ;
    return CAPS.WRITE;
  }

  _predictCost(path, method, intent, cost, h) {
    // Cheap static model. In production this is a small per-route table learned
    // from RESULT.cost_actual — the asymmetry field is what makes it learnable.
    const base = method === 'GET' ? 1 : method === 'SUB' ? 1 : 8;
    const shape = intent.maxShape ? Math.min(intent.maxShape, 64) : 1;
    const declared = cost.predicted || 0;
    // Blend declaration with our own estimate; trust the client only when it
    // claims something *more* expensive (clients under-claim to get served).
    return Math.max(declared, base) + (method === 'GET' ? 0 : shape >> 2);
  }

  _cacheKey(h, method, intent, body) {
    const vary = [h['h4-cache-key'] ?? '', h['accept'] ?? '', h['h4-tenant'] ?? '', String(intent.maxShape ?? 0)];
    const bodyHash = method === 'GET' ? '' : crypto.createHash('sha256').update(body ?? '').digest('base64url').slice(0, 16);
    return this.cache.key([method, h[':path'] ?? '/', ...vary, bodyHash, intent.dedup ?? '']);
  }

  _actualCost(payload, predicted, cacheState) {
    if (cacheState === CACHE.HIT || cacheState === CACHE.HIT_STALE) return 1; // cache hits are ~free
    if (cacheState === CACHE.MEMO) return 1;                                 // shared work, shared cost
    return payload?.cost ?? Math.max(1, Math.round(predicted / 4));
  }

  stats() {
    return {
      ...this.metrics,
      cache: this.cache.sizeInfo(),
      limiter: this.limiter.stats,
      pressure: this.limiter.pressure(),
    };
  }
}

const actualOrZero = (n) => (Number.isFinite(n) ? n : 0);
