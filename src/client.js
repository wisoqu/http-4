// ─────────────────────────────────────────────────────────────────────────────
// H4 client — including an honest local accountant and online cost learner.
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import {
  encodeIntent, encodeCost, encodeCap, encodeHeadersFrame, encodeData,
  decodeResult, decodeRate, decodeCost, decodeReject, decodeHeadersFrame, decodeAccess,
  iterFrames, F, CLASS, MODE,
} from './frames.js';
import { encodeReceipt, signReceipt, solvePoE, CLASS_WEIGHT } from './limits.js';

export class H4Client {
  constructor({
    sessionKey = null,
    budgetPerSec = 40,
    windowMs = 10_000,
    maxTokenBudget = 100_000,
    maxInFlight = 32,
    maxEffortBits = 22,
    passWallet = [],
    log = [],
    respectCeilings = true,
    key = null,
  } = {}) {
    this.sessionKey = sessionKey;
    this.windowMs = windowMs;
    this.budget = Math.floor(budgetPerSec * (windowMs / 1000));
    this.maxTokenBudget = maxTokenBudget;
    this.maxInFlight = maxInFlight;
    this.maxEffortBits = maxEffortBits;
    this.passWallet = [...passWallet];
    this.log = log;
    this.respectCeilings = respectCeilings;
    this.keyPair = key ?? crypto.generateKeyPairSync('ed25519');
    this.learnedBias = new Map();

    this.state = { window: 0, spent: 0, reserved: 0, blockedUntil: 0, nonce: 0 };
    this.stats = {
      sent: 0, sentVirtually: 0, selfBlocked: 0, costAvoided: 0,
      bytesIn: 0, bytesOut: 0, poeSolved: 0, poeBits: 0, poeMs: 0,
      effortRefused: 0, passesSpent: 0,
      rateLimited: 0, deferred: 0, perRequest: [],
    };
  }

  provision({ budget, windowMs, refillPerSec }) {
    if (windowMs) this.windowMs = windowMs;
    if (budget !== undefined) this.budget = budget;
    else if (refillPerSec !== undefined) this.budget = Math.floor(refillPerSec * (this.windowMs / 1000));
    this._roll();
    return this;
  }

  addPasses(passes) {
    if (Array.isArray(passes)) this.passWallet.push(...passes);
    else if (passes) this.passWallet.push(passes);
    return this;
  }

  get window() { return Math.floor(Date.now() / this.windowMs); }

  _roll() {
    const w = this.window;
    if (this.state.window !== w) {
      this.state.window = w;
      this.state.spent = 0;
      this.state.reserved = 0;
    }
  }

  _receipt(weight) {
    this._roll();
    this.state.spent += weight;
    this.state.reserved = Math.max(0, this.state.reserved - weight);
    this.state.nonce += 1;
    const receipt = encodeReceipt({
      window: this.state.window,
      spent: this.state.spent,
      blockedUntil: this.state.blockedUntil,
      nonce: this.state.nonce,
    });
    const mac = this.sessionKey ? signReceipt(receipt, this.sessionKey) : '';
    return { receipt, mac, spent: this.state.spent };
  }

  predictCost({ path = '/', method = 'GET', intent, cost } = {}) {
    const m = method.toUpperCase();
    const base = predict(m, intent, cost);
    const bias = this.learnedBias.get(`${m} ${path}`) ?? 0;
    return Math.max(1, Math.round(base + bias));
  }

  shouldSend({ path = '/', method = 'GET', intent, cost, worth = 0 }) {
    this._roll();
    const now = Date.now();
    if (this.state.blockedUntil > now) {
      this.stats.selfBlocked++;
      this.stats.costAvoided += 1;
      return { send: false, reason: 'self-rate-limited', retryAfterMs: this.state.blockedUntil - now };
    }
    const w = costWeight(method, intent, cost);
    if (this.state.spent + this.state.reserved + w > this.budget) {
      this.state.blockedUntil = (this.state.window + 1) * this.windowMs;
      this.stats.selfBlocked++;
      this.stats.costAvoided += w;
      return { send: false, reason: 'budget', retryAfterMs: this.state.blockedUntil - now };
    }
    const predicted = this.predictCost({ path, method, intent, cost });
    if (this.respectCeilings && worth && predicted > worth) {
      this.stats.selfBlocked++;
      this.stats.costAvoided += predicted;
      return { send: false, reason: 'not-worth-it', predicted, worth };
    }
    if (intent?.maxShape && intent.maxShape > this.maxTokenBudget) {
      return { send: false, reason: 'shape-over-budget' };
    }
    this.state.reserved += w;
    return null;
  }

  build({
    path, method = 'GET', headers = [], intent = {}, cost = {},
    cap = null, body = null, effortNonce = undefined, pass = undefined,
  }) {
    const m = method.toUpperCase();
    const effectiveClass = classifyCost(m, intent, cost);
    const w = CLASS_WEIGHT[effectiveClass] ?? 1;
    const { receipt, mac } = this._receipt(w);

    const hasRl = headers.some(([k]) => k.toLowerCase() === 'h4-rl');
    const hasEffort = headers.some(([k]) => k.toLowerCase() === 'h4-effort');
    const hasPass = headers.some(([k]) => k.toLowerCase() === 'h4-pass');
    const hdrs = [
      [':method', m],
      [':path', path],
      [':scheme', 'https'],
      ...headers,
    ];
    if (this.sessionKey && mac && !hasRl) {
      hdrs.push(['h4-rl', `${receipt},${mac}`]);
    }
    if (effortNonce !== undefined && !hasEffort) {
      hdrs.push(['h4-effort', String(effortNonce)]);
    }
    if (pass && !hasPass) {
      hdrs.push(['h4-pass', String(pass)]);
    }

    const defaultMode = m === 'SUB' ? MODE.SUBSCRIBE : MODE.QUERY;
    const parts = [
      encodeHeadersFrame(hdrs),
      encodeIntent({ mode: defaultMode, ...intent }),
      encodeCost({ costClass: effectiveClass, ...cost }),
    ];
    if (cap) parts.push(encodeCap(cap));
    if (body !== null && body !== undefined) parts.push(encodeData(body));

    const frames = Buffer.concat(parts);
    this.stats.sent++;
    this.stats.bytesOut += frames.length;
    return { frames, receipt, mac, virtualWeight: w };
  }

  observe(respFrames, { path = null, method = 'GET' } = {}) {
    this.stats.bytesIn += respFrames.length;
    const out = {
      result: null, rate: null, cost: null, headers: [],
      reject: null, access: null, body: Buffer.alloc(0),
    };
    const bodyChunks = [];
    for (const f of iterFrames(respFrames)) {
      switch (f.type) {
        case F.RESULT: out.result = decodeResult(f.payload); break;
        case F.RATE: out.rate = decodeRate(f.payload); break;
        case F.COST: out.cost = decodeCost(f.payload); break;
        case F.HEADERS: out.headers = decodeHeadersFrame(f.payload); break;
        case F.ACCESS: out.access = decodeAccess(f.payload); break;
        case F.REJECT:
          out.reject = decodeReject(f.payload);
          if (out.reject.code === 1) this.stats.rateLimited++;
          if (out.reject.code === 10) this.stats.deferred++;
          break;
        case F.DATA: bodyChunks.push(f.payload); break;
        default: break;
      }
    }
    if (bodyChunks.length === 1) out.body = Buffer.from(bodyChunks[0]);
    else if (bodyChunks.length > 1) out.body = Buffer.concat(bodyChunks);

    this._applyPolicy(out, path, method);
    return out;
  }

  _applyPolicy(out, path, method) {
    if (out.rate) {
      this._roll();
      if (out.rate.budgetRemaining === 0) {
        this.state.spent = Math.max(this.state.spent, this.budget);
      } else if (out.rate.budgetRemaining !== undefined && out.rate.refillPerSec > 0) {
        const serverWindowBudget = Math.round(out.rate.refillPerSec * (this.windowMs / 1000));
        const serverSpent = Math.max(0, serverWindowBudget - out.rate.budgetRemaining);
        this.state.spent = Math.max(this.state.spent, serverSpent);
      }
      if (out.rate.blockUntilMs) {
        this.state.blockedUntil = Math.max(this.state.blockedUntil, out.rate.blockUntilMs);
      }
    }
    if (out.reject) {
      if (out.reject.retryAfterMs) {
        this.state.blockedUntil = Math.max(this.state.blockedUntil, Date.now() + out.reject.retryAfterMs);
      }
      if (out.reject.code === 2 || out.reject.code === 4) {
        this.state.blockedUntil = Math.max(this.state.blockedUntil, Date.now() + 30_000);
      }
    }
    if (out.result) {
      if (out.result.memoReuse) {
        this.stats.memoReuse = (this.stats.memoReuse ?? 0) + out.result.memoReuse;
      }
      if (path && Number.isFinite(out.result.costAsym) && out.result.cache === 0) {
        const rk = `${method.toUpperCase()} ${path}`;
        const prev = this.learnedBias.get(rk) ?? 0;
        if (this.learnedBias.size >= 2048 && !this.learnedBias.has(rk)) {
          this.learnedBias.delete(this.learnedBias.keys().next().value);
        }
        this.learnedBias.set(rk, 0.7 * prev + 0.3 * out.result.costAsym);
      }
    }
  }

  /** Pop a single-use pass from the wallet if available (0 CPU burn). */
  takePass() {
    if (this.passWallet.length === 0) return null;
    this.stats.passesSpent++;
    return this.passWallet.shift();
  }

  /**
   * Solve a Proof-of-Effort challenge, enforcing `maxEffortBits` so a rogue
   * server cannot trap the client into unbounded CPU spin.
   */
  payEffort(difficulty) {
    const bits = difficulty.bits ?? difficulty.difficulty ?? 0;
    if (bits > this.maxEffortBits) {
      this.stats.effortRefused++;
      return null;
    }
    let ch = difficulty.challenge;
    let mode = difficulty.mode ?? difficulty.poeMode ?? 'sha256';
    if (!ch && typeof difficulty.detail === 'string') {
      if (difficulty.detail.startsWith('mh:')) {
        mode = 'memhard';
        ch = Buffer.from(difficulty.detail.slice(3), 'base64url');
      } else {
        ch = Buffer.from(difficulty.detail, 'base64url');
      }
    }
    const t0 = process.hrtime.bigint();
    const sol = solvePoE(ch, bits, undefined, mode);
    this.stats.poeMs += Number(process.hrtime.bigint() - t0) / 1e6;
    if (!sol) return null;
    this.stats.poeSolved++;
    this.stats.poeBits += bits;
    return sol.nonce;
  }
}

function classifyCost(method, intent, cost) {
  if (cost?.costClass !== undefined && cost.costClass !== CLASS.CHEAP) return cost.costClass;
  if (cost?.costClass === CLASS.CHEAP && cost && 'costClass' in cost) return CLASS.CHEAP;
  if (intent?.mode === MODE.MUTATE) return cost?.costClass ?? CLASS.EXPENSIVE;
  const m = method.toUpperCase();
  if (m === 'GET' || m === 'HEAD' || m === 'SUB') return CLASS.CHEAP;
  return CLASS.NORMAL;
}

function costWeight(method, intent, cost) {
  return CLASS_WEIGHT[classifyCost(method, intent, cost)] ?? 1;
}

function predict(method, intent, cost) {
  const base = method === 'GET' || method === 'HEAD' || method === 'SUB' ? 1 : 8;
  const shape = intent?.maxShape ? Math.min(intent.maxShape, 64) : 1;
  return Math.max(cost?.predicted || 0, base) + (method === 'GET' || method === 'HEAD' ? 0 : shape >> 2);
}
