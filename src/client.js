// ─────────────────────────────────────────────────────────────────────────────
// H4 client — including the part nobody else ships: an honest local accountant.
//
// The client is not a victim of rate limiting, it is a *participant*. It keeps
// its own budget book, predicts cost before sending, and cancels requests that
// cannot be afforded. On a well-behaved fleet this removes the majority of
// would-be 429s from the wire entirely — the server never sees the traffic, so
// there is nothing to defend against and nothing to pay for.
//
// It also does the defensive half: replay protection, token budget ceilings,
// and refusal to send a request whose predicted cost exceeds what the response
// could possibly be worth. (An agent that cannot evaluate worth is an agent
// that will be mined as a DoS amplifier.)
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import {
  encodeIntent, encodeCost, encodeCap, encodeHeadersFrame, encodeData,
  decodeResult, decodeRate, decodeCost, decodeReject, decodeHeadersFrame,
  iterFrames, F, CLASS, MODE, CAPS,
} from './frames.js';
import { encodeReceipt, signReceipt, solvePoE, decodeReceipt } from './limits.js';

export class H4Client {
  constructor({
    sessionKey = null,
    budgetPerSec = 40,
    windowMs = 10_000,
    maxTokenBudget = 100_000,
    maxInFlight = 32,
    log = [],
    respectCeilings = true,
    key = null,
  } = {}) {
    this.sessionKey = sessionKey;
    this.windowMs = windowMs;
    this.budget = Math.floor(budgetPerSec * (windowMs / 1000));
    this.maxTokenBudget = maxTokenBudget;
    this.maxInFlight = maxInFlight;
    this.log = log;
    this.respectCeilings = respectCeilings;
    this.keyPair = key ?? crypto.generateKeyPairSync('ed25519');

    // `spent` is what we have told the server; `reserved` is what we have
    // decided to send but not yet built. Both must count, otherwise a caller
    // that asks "may I?" in a loop gets "yes" forever.
    this.state = { window: 0, spent: 0, reserved: 0, blockedUntil: 0, nonce: 0 };
    this.stats = {
      sent: 0, sentVirtually: 0, selfBlocked: 0, costAvoided: 0,
      bytesIn: 0, bytesOut: 0, poeSolved: 0, poeBits: 0, poeMs: 0,
      rateLimited: 0, deferred: 0, perRequest: [],
    };
  }

  /**
   * Adopt the server's advertised quota at/after handshake.
   *
   * DESIGN REQUIREMENT (spec §6.4): a client must never guess its budget. If it
   * does, honest accounting and server accounting diverge, and the honest client
   * is the one that gets throttled — the worst possible outcome for a
   * "cooperative" scheme. The server therefore provisions the client, and the
   * client's receipts are expressed in the same units the server enforces.
   */
  provision({ budget, windowMs, refillPerSec }) {
    if (windowMs) this.windowMs = windowMs;
    if (budget !== undefined) this.budget = budget;
    else if (refillPerSec !== undefined) this.budget = Math.floor(refillPerSec * (this.windowMs / 1000));
    this._roll();
    return this;
  }

  get window() { return Math.floor(Date.now() / this.windowMs); }

  _roll() {
    const w = this.window;
    if (this.state.window !== w) { this.state.window = w; this.state.spent = 0; this.state.reserved = 0; }
  }

  /** Honest accounting + the receipt the server will check with one HMAC. */
  _receipt(costWeight) {
    this._roll();
    this.state.spent += costWeight;
    this.state.reserved = Math.max(0, this.state.reserved - costWeight);
    this.state.nonce = (this.state.nonce + 1) & 0x7fffffff;
    const receipt = encodeReceipt({
      window: this.state.window, spent: this.state.spent,
      blockedUntil: Math.floor(this.state.blockedUntil / 1000), nonce: this.state.nonce,
    });
    const mac = this.sessionKey ? signReceipt(receipt, this.sessionKey) : '';
    return { receipt, mac, spent: this.state.spent };
  }

  /**
   * Decide *before* sending. Returns null if the request is affordable, or a
   * reason object if the client should not send it at all.
   */
  shouldSend({ path, method = 'GET', intent, cost, worth = 0 }) {
    this._roll();
    const now = Date.now();
    if (this.state.blockedUntil > now) {
      this.stats.selfBlocked++;
      this.stats.costAvoided += 1;
      return { send: false, reason: 'self-rate-limited', retryAfterMs: this.state.blockedUntil - now };
    }
    const w = costWeight(method, intent, cost);
    if (this.state.spent + this.state.reserved + w > this.budget) {
      // Self-block rather than get 429'd. The server never learns we existed.
      this.state.blockedUntil = (this.state.window + 1) * this.windowMs;
      this.stats.selfBlocked++;
      this.stats.costAvoided += w;
      return { send: false, reason: 'budget', retryAfterMs: this.state.blockedUntil - now };
    }
    const predicted = predict(method, intent, cost);
    if (this.respectCeilings && worth && predicted > worth) {
      this.stats.selfBlocked++;
      this.stats.costAvoided += predicted;
      return { send: false, reason: 'not-worth-it', predicted, worth };
    }
    if (intent?.maxShape && intent.maxShape > this.maxTokenBudget) {
      return { send: false, reason: 'shape-over-budget' };
    }
    this.state.reserved += w; // committed: the caller will now build & send
    return null;
  }

  /** Build the first flight: HEADERS + INTENT + COST (+ CAP). One RTT. */
  build({ path, method = 'GET', headers = [], intent = {}, cost = {}, cap = null, body = null }) {
    const w = costWeight(method, intent, cost);
    const parts = [];
    const hdrs = [
      [':method', method], [':path', path], [':scheme', 'https'],
      ...headers,
    ];
    parts.push(encodeHeadersFrame(hdrs));
    parts.push(encodeIntent({ mode: MODE.QUERY, ...intent }));
    parts.push(encodeCost({ costClass: CLASS.NORMAL, ...cost }));
    if (cap) parts.push(encodeCap(cap));
    if (body) parts.push(encodeData(body));
    const { receipt, mac } = this._receipt(w);
    return Buffer.concat(parts).length + receipt.length + mac.length > 0
      ? { frames: Buffer.concat(parts), receipt, mac, virtualWeight: w }
      : null;
  }

  /** Client-side view of a response: does the server agree with our model? */
  observe(respFrames) {
    const out = { result: null, rate: null, cost: null, headers: [], reject: null, body: Buffer.alloc(0) };
    for (const f of iterFrames(respFrames)) {
      switch (f.type) {
        case F.RESULT: out.result = decodeResult(f.payload); break;
        case F.RATE: out.rate = decodeRate(f.payload); break;
        case F.COST: out.cost = decodeCost(f.payload); break;
        case F.HEADERS: out.headers = decodeHeadersFrame(f.payload); break;
        case F.REJECT:
          out.reject = decodeReject(f.payload);
          if (out.reject.code === 1) this.stats.rateLimited++;
          if (out.reject.code === 10) this.stats.deferred++;
          break;
        case F.DATA: out.body = Buffer.concat([out.body, f.payload]); break;
        default: break;
      }
    }
    this._applyPolicy(out);
    return out;
  }

  _applyPolicy(out) {
    if (out.rate) {
      // Adopt the server's policy eagerly. This is the whole trick: the client
      // stops before the server has to say no again.
      if (out.rate.budgetRemaining !== undefined) {
        this._roll();
        this.state.spent = Math.max(this.state.spent, this.budget - out.rate.budgetRemaining);
      }
      if (out.rate.blockUntilMs) this.state.blockedUntil = Math.max(this.state.blockedUntil, out.rate.blockUntilMs);
    }
    if (out.reject) {
      if (out.reject.retryAfterMs) this.state.blockedUntil = Math.max(this.state.blockedUntil, Date.now() + out.reject.retryAfterMs);
      if (out.reject.code === 2 || out.reject.code === 4) this.state.blockedUntil = Date.now() + 30_000;
    }
    if (out.result?.memoReuse) this.stats.memoReuse = (this.stats.memoReuse ?? 0) + out.result.memoReuse;
  }

  /** Needed when the server escalates to effort: pay once, cache the nonce. */
  payEffort(difficulty) {
    const t0 = process.hrtime.bigint();
    const { nonce } = solvePoE(difficulty.challenge, difficulty.bits) ?? {};
    this.stats.poeSolved++;
    this.stats.poeBits += difficulty.bits;
    this.stats.poeMs += Number(process.hrtime.bigint() - t0) / 1e6;
    return nonce;
  }
}

function costWeight(method, intent, cost) {
  if (cost?.costClass === CLASS.EXPENSIVE) return 60;
  if (cost?.costClass === CLASS.NORMAL) return 5;
  if (method === 'GET' || method === 'HEAD') return 1;
  if (method === 'SUB') return 1;
  return 5;
}

function predict(method, intent, cost) {
  const base = method === 'GET' ? 1 : method === 'SUB' ? 1 : 8;
  const shape = intent?.maxShape ? Math.min(intent.maxShape, 64) : 1;
  return Math.max(cost?.predicted || 0, base) + (method === 'GET' ? 0 : shape >> 2);
}
