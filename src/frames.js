// ─────────────────────────────────────────────────────────────────────────────
// H4 frame layer.
//
// Deliberate non-goals vs HTTP/3:
//   * no SETTINGS handshake sprawl — the 4 things that matter (identity, cost
//     model, rate policy, table version) go in the first frame, once.
//   * no per-request HEADERS waterfall: HEADERS + INTENT always travel together
//     in the first flight, so a request is 1 RTT even on a cold connection
//     (0-RTT via QUIC reuses the previous flight verbatim).
//   * responses are RESULT + DATA, not "header block then body then trailers
//     then maybe an error frame".
//
// Frame = type(varint) | length(varint) | payload
// ─────────────────────────────────────────────────────────────────────────────

import { Writer, Reader, zigzag, unzigzag } from './varint.js';
import { encodeHeaders, decodeHeaders } from './headers.js';

export const F = {
  HEADERS: 0x00,
  DATA: 0x01,
  INTENT: 0x02,
  COST: 0x03,
  CAP: 0x04,
  RESULT: 0x05,
  RATE: 0x06,
  CANCEL: 0x07,
  REJECT: 0x08,
  PATH: 0x09,
  ACCESS: 0x0a,
  PING: 0x0b,
  GOAWAY: 0x0c,
};

// Reject codes: sent instead of a TLS-level drop, cheap to emit, machine-actionable.
export const REJECT = {
  OK: 0,
  RATE_LIMITED: 1,       // retry_after in payload; cost 0
  BUDGET_EXHAUSTED: 2,   // caller must top up h4-budget
  EFFORT_REQUIRED: 3,    // server demands proof-of-effort; payload = difficulty bits
  CAP_INVALID: 4,
  CAP_EXPIRED: 5,
  SCOPE_DENIED: 6,
  AGENT_UNKNOWN: 7,
  COST_REFUSED: 8,       // predicted cost above the caller's declared ceiling
  MALFORMED: 9,
  DEFERRED: 10,          // too hot right now, do not retry before retry_after
};

export const CACHE = { MISS: 0, HIT: 1, HIT_STALE: 2, REVALIDATED: 3, MEMO: 4, COMPUTED: 5 };
export const MODE = { QUERY: 0, MUTATE: 1, SUBSCRIBE: 2 };
export const CLASS = { CHEAP: 0, NORMAL: 1, EXPENSIVE: 2 };

export function frame(type, payload) {
  const w = new Writer(payload.length + 16);
  w.varint(type).varint(payload.length);
  return Buffer.concat([w.finish(), payload]);
}

// ── INTENT: what the caller *means*, not just what it asks for ───────────────
// mode | idempotency-key | deadline-ms | declared-cost-ceiling
// | max-shape (how much the answer may cost) | dedup-key
export function encodeIntent({ mode = MODE.QUERY, idem = '', deadlineMs = 30000, costCeiling = 0, maxShape = 0, dedup = '' } = {}) {
  const w = new Writer(64);
  w.u8(mode);
  w.bytes(Buffer.from(idem));
  w.varint(deadlineMs);
  w.varint(costCeiling);
  w.varint(maxShape);
  w.bytes(Buffer.from(dedup));
  return frame(F.INTENT, w.finish());
}

export function decodeIntent(buf) {
  const r = new Reader(buf);
  return {
    mode: r.u8(),
    idem: r.bytes().toString(),
    deadlineMs: r.varint(),
    costCeiling: r.varint(),
    maxShape: r.varint(),
    dedup: r.bytes().toString(),
  };
}

// ── COST: the economic header. Both directions. ──────────────────────────────
// predicted | costClass | effortBits | budgetRemaining | value (what the caller
// thinks the answer is worth) | tokenBudget (agent-era: max LLM tokens)
export function encodeCost({ predicted = 0, costClass = CLASS.CHEAP, effortBits = 0, budgetRemaining = 0, value = 0, tokenBudget = 0 } = {}) {
  const w = new Writer(48);
  w.varint(predicted);
  w.u8(costClass);
  w.u8(effortBits);
  w.varint(budgetRemaining);
  w.varint(value);
  w.varint(tokenBudget);
  return frame(F.COST, w.finish());
}

export function decodeCost(buf) {
  const r = new Reader(buf);
  return {
    predicted: r.varint(), costClass: r.u8(), effortBits: r.u8(),
    budgetRemaining: r.varint(), value: r.varint(), tokenBudget: r.varint(),
  };
}

// ── CAP: bearer token, but scoped and expiring. ──────────────────────────────
// Opaque to the carrier. HTTP/4 only requires: (1) fixed size prefix so the
// receiver can hash-select a key in O(1), (2) clear expiry, (3) capability
// bitmask so an edge can deny scope *before* waking the origin.
export const CAPS = {
  READ: 1, WRITE: 2, DELEGATE: 4, PAY: 8, PUBLISH: 16, SUBSCRIBE: 32,
};

export function encodeCap({ token = Buffer.alloc(0), expiresAt = 0, caps = 0, scope = '', delegable = 0 } = {}) {
  const w = new Writer(96);
  w.bytes(token);
  w.varint(expiresAt);
  w.varint(caps);
  w.bytes(Buffer.from(scope));
  w.u8(delegable);
  return frame(F.CAP, w.finish());
}

export function decodeCap(buf) {
  const r = new Reader(buf);
  return { token: r.bytes(), expiresAt: r.varint(), caps: r.varint(), scope: r.bytes().toString(), delegable: r.u8() };
}

// ── RESULT: the only way a request ends. Actual cost is always reported. ─────
export function encodeResult({ status = 200, costActual = 0, cache = CACHE.MISS, tokens = 0, memoReuse = 0, wallMs = 0, costAsym = 0, flags = 0 } = {}) {
  const w = new Writer(40);
  w.varint(status);
  w.varint(costActual);
  w.u8(cache);
  w.varint(tokens);
  w.varint(memoReuse);
  w.varint(wallMs);
  w.varint(zigzag(costAsym)); // signed: (actual - predicted), lets clients learn
  w.u8(flags);
  return frame(F.RESULT, w.finish());
}

export function decodeResult(buf) {
  const r = new Reader(buf);
  const status = r.varint(), costActual = r.varint(), cache = r.u8();
  const tokens = r.varint(), memoReuse = r.varint(), wallMs = r.varint();
  const costAsym = unzigzag(r.varint());
  return { status, costActual, cache, tokens, memoReuse, wallMs, costAsym, flags: r.u8() };
}

// ── RATE: server → client budget/burn-rate policy. This is the load-shedding
// primitive: it is cheaper to tell a client "you have 40 units and are burning
// 9/s, block until T" than to serve 300 requests and close the socket. ────────
export function encodeRate({ pressure = 0, budgetRemaining = 0, refillPerSec = 0, blockUntilMs = 0, penaltyMs = 0 } = {}) {
  const w = new Writer(24);
  w.u8(pressure);
  w.varint(budgetRemaining);
  w.varint(refillPerSec);
  w.varint(blockUntilMs);
  w.varint(penaltyMs);
  return frame(F.RATE, w.finish());
}

export function decodeRate(buf) {
  const r = new Reader(buf);
  return {
    pressure: r.u8(), budgetRemaining: r.varint(), refillPerSec: r.varint(),
    blockUntilMs: r.varint(), penaltyMs: r.varint(),
  };
}

export function encodeReject(code, { retryAfterMs = 0, difficulty = 0, detail = '' } = {}) {
  const w = new Writer(32);
  w.u8(code);
  w.varint(retryAfterMs);
  w.u8(difficulty);
  w.bytes(Buffer.from(detail));
  return frame(F.REJECT, w.finish());
}

export function decodeReject(buf) {
  const r = new Reader(buf);
  return { code: r.u8(), retryAfterMs: r.varint(), difficulty: r.u8(), detail: r.bytes().toString() };
}

export function encodeHeadersFrame(headers) { return frame(F.HEADERS, encodeHeaders(headers)); }
export function decodeHeadersFrame(buf) { return decodeHeaders(buf); }

export function encodeData(buf) { return frame(F.DATA, Buffer.from(buf)); }

export function encodeGoaway({ lastStream = 0, reason = 0 } = {}) {
  const w = new Writer(16); w.varint(lastStream).u8(reason);
  return frame(F.GOAWAY, w.finish());
}

// ── Frame iterator: zero-copy-ish split, tolerant of partial buffers ─────────
export function* iterFrames(buf) {
  let off = 0;
  while (off < buf.length) {
    const r = new Reader(buf.subarray(off));
    const type = r.varint();
    const len = r.varint();
    const start = off + r.off;
    yield { type, payload: buf.subarray(start, start + len) };
    off = start + len;
  }
}
