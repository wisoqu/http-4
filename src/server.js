// ─────────────────────────────────────────────────────────────────────────────
// H4 origin server (semantics layer, wire-agnostic).
//
// DESIGN RULE THAT DRIVES THIS FILE:
//   security checks are ordered by ascending cost, and every check that can be
//   answered "no" without touching the origin does so.
//
//   0. structural + header + 0-RTT check  ~100 ns   (anti-smuggling, replay guard)
//   1. capability verify                  ~1-4 µs   (C11 HMAC chain; root cached)
//   2. limit + h4-pass + inline PoE       ~0.1-3 µs (receipt / pass / C11 PoE)
//   3. scope & capability gate            ~200 ns   (segment-safe containment)
//   4. cost & deadline gate               ~200 ns   (table + EMA estimate)
//   5. dedup / idem / coalesce / stream   ~1 µs     (singleflight or live stream)
//   6. handler                            expensive ← nothing hostile reaches here
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import {
  REJECT, CLASS, MODE, CACHE,
  encodeResult, encodeRate, encodeReject, encodeHeadersFrame, encodeData, encodeCost, encodeAccess,
} from './frames.js';
import { verify, KeyRegistry, verifyCache, CAPS, isValidPath, isSubScope } from './identity.js';
import { Limiter, poeChallenge } from './limits.js';
import { H4Cache } from './cache.js';

const DEADLINE_EXCEEDED = Symbol('DEADLINE_EXCEEDED');

/**
 * Canonicalize peer IP addresses so dual-stack callers (`::ffff:203.0.113.5` vs
 * `203.0.113.5`) share one aggregate network bucket and cannot double anonymous quota.
 */
export function normalizePeerIp(ip) {
  if (!ip || typeof ip !== 'string') return 'anon';
  let s = ip.trim();
  const zoneIdx = s.indexOf('%');
  if (zoneIdx !== -1) s = s.slice(0, zoneIdx);
  const lower = s.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const v4 = s.slice(7);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v4)) return v4;
  }
  return lower || 'anon';
}

function isAsyncIterable(v) {
  return v !== null && typeof v === 'object' && typeof v[Symbol.asyncIterator] === 'function';
}

function hasControlChars(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0 || c === 10 || c === 13) return true;
  }
  return false;
}

export class H4Server {
  constructor({
    routes = {},
    registry = new KeyRegistry(),
    limiter = new Limiter(),
    cache = new H4Cache(),
    accessLog = null,
    requireCap = false,
    emitAccess = false,
  } = {}) {
    this.routes = routes;
    this.registry = registry;
    this.limiter = limiter;
    this.cache = cache;
    this.accessLog = accessLog;
    this.requireCap = requireCap;
    this.emitAccess = emitAccess;
    this.verifyCache = verifyCache;
    this.routeCosts = new Map();
    this.idemStore = new Map();
    this.metrics = {
      requests: 0, served: 0, streamed: 0, streamCancelled: 0, rejected: 0,
      coalesced: 0, cacheHits: 0, capVerifies: 0, poeChecks: 0, passRedeemed: 0,
      costPredicted: 0, bytesIn: 0, bytesOut: 0,
      savedByCacheMs: 0, savedByCoalesceMs: 0, deferred: 0, idempotentReplays: 0,
    };
  }

  /** Register a unary or streaming route handler. */
  route(method, path, handler) {
    this.routes[`${method.toUpperCase()} ${path}`] = handler;
    return this;
  }

  /**
   * Shared pre-handler security & admission pipeline (steps 0..4).
   * Guarantees identical enforcement for unary `handle()` and streaming `handleStream()`.
   */
  _admit(req, now) {
    this.metrics.requests++;
    if (req.byteLength) this.metrics.bytesIn += req.byteLength;
    else if (req.body) this.metrics.bytesIn += Buffer.byteLength(req.body);

    // ── 0. structural & anti-smuggling validation ───────────────────────────
    const headers = req.headers ?? [];
    if (!Array.isArray(headers) || headers.length > 256) {
      return { ok: false, response: this._reject(REJECT.MALFORMED, 'invalid headers') };
    }
    const h = Object.create(null);
    let seenRegularHeader = false;
    let totalHeaderBytes = 0;
    for (let i = 0; i < headers.length; i++) {
      const pair = headers[i];
      if (!pair || typeof pair[0] !== 'string') {
        return { ok: false, response: this._reject(REJECT.MALFORMED, 'bad header entry') };
      }
      const k = pair[0];
      const v = typeof pair[1] === 'string' ? pair[1] : String(pair[1] ?? '');
      if (k.length === 0 || k.length > 256) {
        return { ok: false, response: this._reject(REJECT.MALFORMED, 'invalid header name length') };
      }
      totalHeaderBytes += k.length + v.length;
      if (totalHeaderBytes > 32 * 1024) {
        return { ok: false, response: this._reject(REJECT.MALFORMED, 'header block exceeds 32KB') };
      }
      if (hasControlChars(k) || hasControlChars(v)) {
        return { ok: false, response: this._reject(REJECT.MALFORMED, 'control char in header') };
      }
      if (k.charCodeAt(0) === 58) {
        if (seenRegularHeader) return { ok: false, response: this._reject(REJECT.MALFORMED, 'pseudo-header after regular header') };
        if (k in h) return { ok: false, response: this._reject(REJECT.MALFORMED, `duplicate pseudo-header ${k}`) };
      } else {
        seenRegularHeader = true;
      }
      h[k] = v;
    }

    const rawPath = h[':path'] ?? '/';
    if (typeof rawPath !== 'string' || rawPath.length === 0 || rawPath.length > 8192) {
      return { ok: false, response: this._reject(REJECT.MALFORMED, 'bad path') };
    }
    const qIdx = rawPath.indexOf('?');
    const pathname = qIdx === -1 ? rawPath : rawPath.slice(0, qIdx);
    const query = qIdx === -1 ? '' : rawPath.slice(qIdx + 1);
    if (!isValidPath(pathname)) {
      return { ok: false, response: this._reject(REJECT.MALFORMED, 'invalid or traversal path') };
    }

    const method = (h[':method'] ?? 'GET').toUpperCase();
    const intent = req.intent ?? { mode: MODE.QUERY, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' };
    const cost = req.cost ?? { predicted: 0, costClass: CLASS.CHEAP, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 };
    const cap = req.cap ?? null;
    const earlyData = Boolean(req.earlyData || h['early-data'] === '1');

    // ── 0b. 0-RTT replay guard (RFC 8470 semantics) ─────────────────────────
    if (earlyData) {
      const safeFor0Rtt = (method === 'GET' || method === 'HEAD') && intent.mode !== MODE.MUTATE;
      if (!safeFor0Rtt && !intent.idem) {
        this.metrics.deferred++;
        return { ok: false, response: this._reject(REJECT.DEFERRED, '0rtt-unsafe-mutate', 0) };
      }
    }

    // ── 1. identity (only if a token is present, or required) ───────────────
    let identity = null;
    if (h['h4-cap'] && h['h4-cap'].length > 11000) {
      return { ok: false, response: this._reject(REJECT.MALFORMED, 'oversized h4-cap header') };
    }
    const rawToken = cap?.token?.length
      ? cap.token
      : (h['h4-cap'] ? Buffer.from(h['h4-cap'], 'base64url') : null);
    if (rawToken && rawToken.length) {
      this.metrics.capVerifies++;
      const v = verify(rawToken, this.registry, { now, cache: this.verifyCache, required: 0 });
      if (!v.ok) return { ok: false, response: this._reject(REJECT[v.code] ?? REJECT.CAP_INVALID, v.why) };
      identity = v;
    } else if (this.requireCap) {
      return { ok: false, response: this._reject(REJECT.CAP_INVALID, 'capability required') };
    }

    // ── limiting keys (with IPv4-mapped IPv6 canonicalization) ──────────────
    const peerNorm = req.peer ? normalizePeerIp(req.peer) : null;
    const instanceId = h['h4-agent-instance'] || '';
    const subject = identity
      ? crypto.createHash('sha256').update(`${identity.subject}|${instanceId}`).digest('hex').slice(0, 16)
      : this._subjectFromRequest(peerNorm, h);
    const net = identity ? identity.grant : peerNorm;
    const netAllowance = identity
      ? this.limiter.budget * (1 + this.limiter.identityBonus) * Math.max(1, Math.min(identity.maxSubs || 1, 4096))
      : 0;

    // ── 2. limits (cooperative receipt → enforced → h4-pass → inline PoE) ───
    let rl = req.rate ?? null;
    if (!rl && h['h4-rl']) {
      const comma = h['h4-rl'].indexOf(',');
      if (comma > 0) rl = { receipt: h['h4-rl'].slice(0, comma), mac: h['h4-rl'].slice(comma + 1) };
    }
    const effortNonce = req.effortNonce !== undefined
      ? req.effortNonce
      : (h['h4-effort'] !== undefined && h['h4-effort'] !== '' ? Number(h['h4-effort']) : undefined);
    const passToken = req.pass ?? h['h4-pass'] ?? null;

    const costClass = this._classify(pathname, method, intent, cost);
    let limit = this.limiter.check({
      subject, net, netAllowance, costClass,
      receipt: rl?.receipt, mac: rl?.mac, sessionKey: req.sessionKey ?? null,
      identityTrusted: !!identity, earlyData,
    }, now);

    if (!limit.allow) {
      if (limit.code === 'EFFORT_REQUIRED') {
        // Tier 3a: zero-CPU single-use pass bypass (`h4-pass`)
        const passAdmit = passToken
          ? this.limiter.redeemPass({ subject, net, passToken, costClass }, now)
          : null;
        if (passAdmit) {
          this.metrics.passRedeemed++;
          limit = passAdmit;
        } else {
          // Tier 3b: inline Proof-of-Effort (`sha256` or 4 KB `memhard`)
          this.metrics.poeChecks++;
          const poeMode = limit.poeMode ?? this.limiter.poeMode ?? 'sha256';
          const poeWindow = Math.floor(now / 30_000);
          const ch = poeChallenge(subject, poeWindow, poeMode);
          const redeemed = effortNonce !== undefined
            ? this.limiter.redeemPoE({
                subject, net, poeWindow, challenge: ch,
                nonce: effortNonce, difficulty: limit.difficulty, costClass, mode: poeMode,
              }, now)
            : null;
          if (redeemed) {
            limit = redeemed;
          } else {
            this.metrics.rejected++;
            const chStr = poeMode === 'memhard'
              ? `mh:${ch.toString('base64url')}`
              : ch.toString('base64url');
            return {
              ok: false,
              response: {
                reject: { code: REJECT.EFFORT_REQUIRED, difficulty: limit.difficulty, retryAfterMs: 0, detail: chStr, poeMode },
                frames: [encodeReject(REJECT.EFFORT_REQUIRED, { difficulty: limit.difficulty, detail: chStr })],
                rate: null, cost: 0,
              },
            };
          }
        }
      } else {
        this.metrics.rejected++;
        return {
          ok: false,
          response: {
            reject: { code: REJECT.RATE_LIMITED, retryAfterMs: limit.retryAfterMs, difficulty: 0, detail: '' },
            frames: [encodeReject(REJECT.RATE_LIMITED, { retryAfterMs: limit.retryAfterMs })],
            rate: encodeRate({
              pressure: limit.pressure, budgetRemaining: 0,
              refillPerSec: Math.floor(this.limiter.budget / (this.limiter.windowMs / 1000)),
              blockUntilMs: now + limit.retryAfterMs, penaltyMs: limit.retryAfterMs,
            }),
            cost: 0,
          },
        };
      }
    }

    // ── 3. scope / capability gate before any work ──────────────────────────
    if (identity) {
      const need = this._requiredCaps(pathname, method, intent);
      if ((identity.caps & need) !== need) {
        return { ok: false, response: this._reject(REJECT.SCOPE_DENIED, 'insufficient scope') };
      }
      if (!isSubScope(identity.scope, pathname)) {
        return { ok: false, response: this._reject(REJECT.SCOPE_DENIED, 'path outside token scope') };
      }
    }

    // ── 4. cost & deadline gate: refuse before spending ─────────────────────
    if (intent.deadlineMs !== undefined && intent.deadlineMs < 0) {
      this.metrics.deferred++;
      return { ok: false, response: this._reject(REJECT.DEFERRED, 'expired deadline', 250) };
    }
    const predicted = this._predictCost(pathname, method, intent, cost);
    this.metrics.costPredicted++;
    if (intent.costCeiling && predicted > intent.costCeiling) {
      return { ok: false, response: this._reject(REJECT.COST_REFUSED, `predicted ${predicted} > ceiling ${intent.costCeiling}`) };
    }
    if (cost.tokenBudget && intent.maxShape && intent.maxShape > cost.tokenBudget) {
      return { ok: false, response: this._reject(REJECT.COST_REFUSED, 'shape exceeds token budget') };
    }

    const advertised = {
      budget: limit.effectiveBudget ?? this.limiter.budget,
      budgetRemaining: limit.budgetRemaining ?? this.limiter.budget,
      windowMs: this.limiter.windowMs,
      refillPerSec: Math.floor((limit.effectiveBudget ?? this.limiter.budget) / (this.limiter.windowMs / 1000)),
      trusted: !!identity,
    };

    return {
      ok: true,
      ctx: {
        h, rawPath, pathname, query, method, intent, cost, identity,
        subject, net, costClass, limit, predicted, advertised, earlyData,
      },
    };
  }

  /**
   * Unary request handling. Reject and cache-hit paths never yield the event loop.
   */
  async handle(req, now = Date.now()) {
    const adm = this._admit(req, now);
    if (!adm.ok) return adm.response;
    const {
      h, rawPath, pathname, query, method, intent, cost, identity,
      subject, costClass, limit, predicted, advertised,
    } = adm.ctx;

    // ── 5. idempotency + tenant-isolated cache + coalescing ─────────────────
    const tenantTag = identity ? `id:${identity.tenant}` : `anon:${h['h4-tenant'] ?? ''}`;
    if (intent.idem) {
      const idemKey = `${subject}|${tenantTag}|${method}|${rawPath}|${intent.idem}`;
      const prior = this.idemStore.get(idemKey);
      if (prior && prior.expiresAt > now) {
        this.metrics.idempotentReplays++;
        return this._buildSuccessResponse({
          payload: prior.payload, cacheState: CACHE.MEMO, predicted, costClass,
          tokens: prior.tokens, memoReuse: prior.memoReuse + 1, wallMs: 0,
          limit, cost, advertised, method, path: pathname, subject, now,
          includeAccess: this.emitAccess || 'h4-trace' in h,
        });
      }
    }

    const lookupMethod = method === 'HEAD' && !Object.hasOwn(this.routes, `HEAD ${pathname}`) ? 'GET' : method;
    const cacheKey = this._cacheKey(h, lookupMethod, rawPath, tenantTag, intent, req.body);
    const useDedup = Boolean(intent.dedup || intent.idem || lookupMethod === 'GET');
    const started = process.hrtime.bigint();

    let payload, cacheState, tokens = 0, memoReuse = 0;
    const cached = lookupMethod === 'GET' || intent.dedup ? this.cache.get(cacheKey, now) : null;
    if (cached) {
      payload = cached.value;
      cacheState = cached.stale ? CACHE.HIT_STALE : CACHE.MISS === -1 ? 0 : CACHE.HIT;
      this.metrics.cacheHits++;
      this.metrics.savedByCacheMs += cached.computeMs ?? 0;
    } else {
      const route = this._findRoute(lookupMethod, pathname);
      if (!route) return this._reject(REJECT.MALFORMED, 'no route');

      const deadlineMs = intent.deadlineMs > 0 ? intent.deadlineMs : 0;
      const run = async () => {
        const t0 = process.hrtime.bigint();
        let timer = null;
        try {
          let out = await Promise.resolve(route({
            path: pathname, rawPath, query, method, headers: h, body: req.body,
            intent, cost, identity, now, remainingMs: deadlineMs || 30_000,
          }));
          // If an async-generator route is invoked via unary handle(), collect chunks cleanly
          if (isAsyncIterable(out) || isAsyncIterable(out?.stream)) {
            const iter = isAsyncIterable(out) ? out : out.stream;
            const chunks = [];
            let count = 0;
            for await (const ch of iter) {
              chunks.push(Buffer.isBuffer(ch) ? ch : Buffer.from(typeof ch === 'string' ? ch : JSON.stringify(ch)));
              count++;
            }
            out = {
              status: out?.status ?? 200,
              type: out?.type ?? 'application/octet-stream',
              body: Buffer.concat(chunks),
              tokens: count,
              cost: out?.cost ?? Math.max(1, count),
            };
          }
          const workP = Promise.resolve(out);
          const raced = deadlineMs > 0
            ? await Promise.race([
                workP,
                new Promise((resolve) => {
                  timer = setTimeout(() => resolve(DEADLINE_EXCEEDED), deadlineMs);
                  timer.unref?.();
                }),
              ])
            : await workP;
          if (raced === DEADLINE_EXCEEDED) return { deferred: true, ms: deadlineMs };
          const ms = Number(process.hrtime.bigint() - t0) / 1e6;
          return { out: raced, ms, deferred: false };
        } finally {
          if (timer) clearTimeout(timer);
        }
      };

      // Note: race deadline around the whole route invocation (not after awaiting)
      const runWithDeadline = async () => {
        if (deadlineMs <= 0) return run();
        let timer = null;
        try {
          const res = await Promise.race([
            run(),
            new Promise((resolve) => {
              timer = setTimeout(() => resolve({ deferred: true, ms: deadlineMs }), deadlineMs);
              timer.unref?.();
            }),
          ]);
          return res;
        } finally {
          if (timer) clearTimeout(timer);
        }
      };

      if (useDedup) {
        const res = await this.cache.coalesce(cacheKey, runWithDeadline);
        if (res.value.deferred) {
          this.metrics.deferred++;
          return this._reject(REJECT.DEFERRED, `deadline ${deadlineMs}ms exceeded`, Math.min(deadlineMs * 2, 5000));
        }
        if (res.coalesced) {
          cacheState = CACHE.MEMO;
          this.metrics.coalesced++;
          this.metrics.savedByCoalesceMs += res.value.ms;
          memoReuse = 1;
        } else {
          cacheState = CACHE.MISS;
        }
        if (!res.coalesced && res.value.out !== undefined && (lookupMethod === 'GET' || intent.dedup)) {
          const outStatus = res.value.out.status ?? 200;
          const explicitTtl = res.value.out.ttlMs;
          if (outStatus < 500 || (explicitTtl !== undefined && explicitTtl > 0)) {
            const ttl = explicitTtl ?? this.cache.defaultTtlMs;
            this.cache.set(cacheKey, res.value.out, { ttlMs: ttl, computeMs: res.value.ms, memo: false, now });
          }
        }
        payload = res.value.out;
      } else {
        const r = await runWithDeadline();
        if (r.deferred) {
          this.metrics.deferred++;
          return this._reject(REJECT.DEFERRED, `deadline ${deadlineMs}ms exceeded`, Math.min(deadlineMs * 2, 5000));
        }
        payload = r.out;
        cacheState = CACHE.COMPUTED;
      }
      tokens = payload?.tokens ?? 0;
      memoReuse = Math.max(memoReuse, payload?.memoReuse ?? 0);

      if (payload?.cost !== undefined && Number.isFinite(payload.cost)) {
        const rk = `${lookupMethod} ${pathname}`;
        const prev = this.routeCosts.get(rk);
        if (this.routeCosts.size >= 4096 && prev === undefined) {
          this.routeCosts.delete(this.routeCosts.keys().next().value);
        }
        this.routeCosts.set(rk, prev === undefined ? payload.cost : 0.7 * prev + 0.3 * payload.cost);
      }
    }

    if (intent.idem && payload !== undefined) {
      const idemKey = `${subject}|${tenantTag}|${method}|${rawPath}|${intent.idem}`;
      if (this.idemStore.size >= 10000) this.idemStore.delete(this.idemStore.keys().next().value);
      this.idemStore.set(idemKey, {
        expiresAt: now + Math.max(intent.deadlineMs || 30_000, 60_000),
        payload, tokens, memoReuse,
      });
    }

    const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
    return this._buildSuccessResponse({
      payload, cacheState, predicted, costClass, tokens, memoReuse, wallMs,
      limit, cost, advertised, method, path: pathname, subject, now,
      includeAccess: this.emitAccess || 'h4-trace' in h,
    });
  }

  /**
   * First-class streaming (`MODE.SUBSCRIBE` / token streaming / SSE translation).
   *
   * Streams `HEADERS`, live `DATA` chunks via `onFrame`, aborts generation
   * immediately when `signal` fires (`F.CANCEL` from client) or `deadlineMs`
   * expires, refunds unspent budget on early cancel, and finishes with
   * `COST` + `RATE` + `RESULT` trailers reporting exact partial cost & tokens.
   */
  async handleStream(req, { signal = null, onFrame = () => {}, now = Date.now() } = {}) {
    const adm = this._admit(req, now);
    if (!adm.ok) {
      for (const f of adm.response.frames) onFrame(f);
      return adm.response;
    }
    const {
      h, rawPath, pathname, query, method, intent, cost, identity,
      subject, net, costClass, limit, predicted, advertised,
    } = adm.ctx;

    const route = this._findRoute(method, pathname);
    if (!route) {
      const rej = this._reject(REJECT.MALFORMED, 'no route');
      for (const f of rej.frames) onFrame(f);
      return rej;
    }

    const ac = new AbortController();
    let timer = null;
    const onAbort = () => ac.abort(signal?.reason ?? 'cancelled');
    if (signal) {
      if (signal.aborted) ac.abort(signal.reason ?? 'cancelled');
      else signal.addEventListener('abort', onAbort, { once: true });
    }
    if (intent.deadlineMs > 0) {
      timer = setTimeout(() => ac.abort('deadline'), intent.deadlineMs);
      timer.unref?.();
    }

    const started = process.hrtime.bigint();
    const emittedFrames = [];
    const emit = (f) => {
      emittedFrames.push(f);
      this.metrics.bytesOut += f.length;
      onFrame(f);
    };

    let chunks = 0;
    let costActual = 0;
    let cancelled = false;

    try {
      const out = await route({
        path: pathname, rawPath, query, method, headers: h, body: req.body,
        intent, cost, identity, now, signal: ac.signal,
        remainingMs: intent.deadlineMs || 30_000,
      });

      const iter = isAsyncIterable(out) ? out : (isAsyncIterable(out?.stream) ? out.stream : null);
      if (!iter) {
        // Unary route accessed via handleStream: emit full response frames
        const res = this._buildSuccessResponse({
          payload: out, cacheState: CACHE.COMPUTED, predicted, costClass,
          tokens: out?.tokens ?? 0, memoReuse: 0,
          wallMs: Number(process.hrtime.bigint() - started) / 1e6,
          limit, cost, advertised, method, path: pathname, subject, now,
          includeAccess: this.emitAccess || 'h4-trace' in h,
        });
        for (const f of res.frames) onFrame(f);
        return res;
      }

      const status = out?.status ?? 200;
      const contentType = out?.type ?? 'application/x-ndjson';
      const costPerChunk = out?.costPerChunk ?? 1;

      emit(encodeHeadersFrame([
        [':status', String(status)],
        ['content-type', contentType],
        ['h4-stream', '1'],
        ['h4-predicted', String(predicted)],
      ]));

      for await (const item of iter) {
        if (ac.signal.aborted) {
          cancelled = true;
          break;
        }
        if (intent.costCeiling > 0 && costActual + costPerChunk > intent.costCeiling) {
          cancelled = true;
          ac.abort('cost-ceiling');
          break;
        }
        const buf = Buffer.isBuffer(item)
          ? item
          : Buffer.from(typeof item === 'string' ? item : JSON.stringify(item) + '\n');
        chunks++;
        costActual += costPerChunk;
        emit(encodeData(buf));
        if (ac.signal.aborted) {
          cancelled = true;
          break;
        }
      }
    } catch (err) {
      if (ac.signal.aborted || err?.name === 'AbortError') {
        cancelled = true;
      } else {
        throw err;
      }
    } finally {
      if (timer) clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
    }

    if (cancelled) {
      this.metrics.streamCancelled++;
      const reservedWeight = predicted > costActual ? predicted - costActual : 0;
      if (reservedWeight > 0) {
        this.limiter.refund({ subject, net, units: Math.min(reservedWeight, 5) }, now);
      }
    }

    const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
    const finalCost = Math.max(cancelled && chunks === 0 ? 0 : 1, Math.round(costActual));
    emit(encodeCost({
      predicted, costClass, effortBits: 0, budgetRemaining: limit.budgetRemaining,
      value: cost.value, tokenBudget: chunks,
    }));
    emit(encodeRate({
      pressure: limit.pressure, budgetRemaining: limit.budgetRemaining,
      refillPerSec: Math.floor((limit.effectiveBudget ?? this.limiter.budget) / (this.limiter.windowMs / 1000)),
      blockUntilMs: limit.blockUntilMs ?? 0, penaltyMs: 0,
    }));
    emit(encodeResult({
      status: cancelled ? 206 : 200,
      costActual: finalCost,
      cache: CACHE.COMPUTED,
      tokens: chunks,
      memoReuse: 0,
      wallMs: Math.round(wallMs),
      costAsym: finalCost - predicted,
      flags: cancelled ? 1 : 0,
    }));

    this.metrics.served++;
    this.metrics.streamed++;

    return {
      result: { status: cancelled ? 206 : 200, costActual: finalCost, cache: CACHE.COMPUTED, tokens: chunks, wallMs, cancelled },
      advertised,
      frames: emittedFrames,
      rate: limit,
      cost: finalCost,
    };
  }

  _buildSuccessResponse({
    payload, cacheState, predicted, costClass, tokens, memoReuse, wallMs,
    limit, cost, advertised, method, path, subject, now, includeAccess,
  }) {
    const costActual = this._actualCost(payload, predicted, cacheState);
    const status = payload?.status ?? 200;
    const head = [
      [':status', String(status)],
      ['content-type', payload?.type ?? 'application/json'],
      ['h4-cache', cacheState === CACHE.HIT ? 'hit' : cacheState === CACHE.HIT_STALE ? 'stale' : cacheState === CACHE.MEMO ? 'memo' : 'miss'],
      ['h4-cost', String(costActual)],
      ['h4-predicted', String(predicted)],
    ];
    const headFrame = encodeHeadersFrame(head);
    const rawBody = method === 'HEAD'
      ? Buffer.alloc(0)
      : (Buffer.isBuffer(payload?.body)
          ? payload.body
          : Buffer.from(typeof payload?.body === 'string' ? payload.body : JSON.stringify(payload?.body ?? {})));

    const frames = [
      encodeResult({
        status, costActual, cache: cacheState,
        tokens, memoReuse, wallMs: Math.round(wallMs),
        costAsym: actualOrZero(costActual) - predicted,
      }),
      encodeRate({
        pressure: limit.pressure, budgetRemaining: limit.budgetRemaining,
        refillPerSec: Math.floor((limit.effectiveBudget ?? this.limiter.budget) / (this.limiter.windowMs / 1000)),
        blockUntilMs: limit.blockUntilMs ?? 0, penaltyMs: 0,
      }),
      encodeCost({
        predicted, costClass, effortBits: 0, budgetRemaining: limit.budgetRemaining,
        value: cost.value, tokenBudget: tokens,
      }),
      headFrame,
      encodeData(rawBody),
    ];
    if (includeAccess) {
      frames.push(encodeAccess({
        tier: limit.tier.join('+'),
        cache: cacheState,
        costActual,
        predicted,
        wallUs: Math.round(wallMs * 1000),
      }));
    }

    this.metrics.served++;
    for (let i = 0; i < frames.length; i++) this.metrics.bytesOut += frames[i].length;

    if (this.accessLog) {
      this.accessLog.push({
        t: now, method, path, subject, status,
        cache: cacheState, costActual, predicted, wallMs: +wallMs.toFixed(3),
        tier: limit.tier.join('+'),
      });
    }

    return {
      result: { status, costActual, cache: cacheState, tokens, wallMs },
      advertised,
      frames, rate: limit, cost: costActual,
    };
  }

  _findRoute(method, pathname) {
    const specific = `${method} ${pathname}`;
    if (Object.hasOwn(this.routes, specific)) return this.routes[specific];
    if (Object.hasOwn(this.routes, pathname)) return this.routes[pathname];
    return null;
  }

  _reject(code, detail, retryAfterMs = 0) {
    this.metrics.rejected++;
    return {
      reject: { code, detail, retryAfterMs, difficulty: 0 },
      frames: [encodeReject(code, { detail, retryAfterMs })],
      rate: null, cost: 0,
    };
  }

  _subjectFromRequest(peerNorm, h) {
    const inst = h['h4-agent-instance'] || h['h4-agent'] || '';
    const net = peerNorm ?? 'anon';
    return crypto.createHash('sha256').update(`${inst}|${net}`).digest('hex').slice(0, 16);
  }

  _classify(path, method, intent, cost) {
    if (cost?.costClass !== undefined && cost.costClass !== CLASS.CHEAP) return cost.costClass;
    if (intent?.mode === MODE.MUTATE) return CLASS.EXPENSIVE;
    if (method === 'GET' || method === 'HEAD' || method === 'SUB') return CLASS.CHEAP;
    return CLASS.NORMAL;
  }

  _requiredCaps(path, method, intent) {
    if (method === 'SUB' || intent?.mode === MODE.SUBSCRIBE) return CAPS.SUBSCRIBE;
    if (method === 'GET' || method === 'HEAD') return CAPS.READ;
    return CAPS.WRITE;
  }

  _predictCost(path, method, intent, cost) {
    const learned = this.routeCosts.get(`${method} ${path}`);
    const base = learned !== undefined
      ? Math.max(1, Math.round(learned))
      : (method === 'GET' || method === 'HEAD' || method === 'SUB' ? 1 : 8);
    const shape = intent.maxShape ? Math.min(intent.maxShape, 64) : 1;
    const declared = cost.predicted || 0;
    return Math.max(declared, base) + (method === 'GET' || method === 'HEAD' ? 0 : shape >> 2);
  }

  _cacheKey(h, method, rawPath, tenantTag, intent, body) {
    const vary = [h['h4-cache-key'] ?? '', h['accept'] ?? '', tenantTag, String(intent.maxShape ?? 0)];
    const bodyHash = method === 'GET'
      ? ''
      : crypto.createHash('sha256').update(body ?? '').digest('base64url').slice(0, 16);
    return this.cache.key([method, rawPath, ...vary, bodyHash, intent.dedup ?? '']);
  }

  _actualCost(payload, predicted, cacheState) {
    if (cacheState === CACHE.HIT || cacheState === CACHE.HIT_STALE) return 1;
    if (cacheState === CACHE.MEMO) return 1;
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

const actualOrZero = (n) => (Number.isFinite(n) && n >= 0 ? Math.round(n) : 0);

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [{ createGateway }] = await Promise.all([import('./gateway.js')]);
  const port = Number(process.env.PORT ?? 8080);
  const h4 = new H4Server({
    routes: {
      'GET /': async () => ({ status: 200, body: { proto: 'h4/1', ok: true }, cost: 1, ttlMs: 5000 }),
      'GET /health': async () => ({ status: 200, body: { healthy: true }, cost: 1, ttlMs: 1000 }),
    },
  });
  const gw = createGateway({ handler: h4 });
  gw.listen(port, '0.0.0.0', () => {
    console.log(`H4 gateway server listening on http://0.0.0.0:${port}`);
  });
}
