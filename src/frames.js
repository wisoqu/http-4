// ─────────────────────────────────────────────────────────────────────────────
// H4 frame layer.
//
// Deliberate non-goals vs HTTP/3:
//   * no SETTINGS handshake sprawl — the 4 things that matter (identity, cost
//     model, rate policy, table version) go in the HELLO control frame, once.
//   * no per-request HEADERS waterfall: HEADERS + INTENT always travel together
//     in the first flight, so a request is 1 RTT even on a cold connection.
//   * responses are RESULT + RATE + COST + HEADERS + DATA, not "header block
//     then body then trailers then maybe an error frame".
//
// Frame = type(varint) | length(varint) | payload
// ─────────────────────────────────────────────────────────────────────────────

import { Writer, Reader, varintSize, writeVarint, zigzag, unzigzag } from './varint.js';
import { encodeHeaders, decodeHeaders, TABLE_VERSION } from './headers.js';
import { CAPS } from './identity.js';

export { CAPS };

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
  HELLO: 0x0d, // QUIC control-stream frame (spec §3.2 / §4: proto, tableVersion, ratePolicy, sessionKey)
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
  DEFERRED: 10,          // too hot / deadline exceeded, do not retry before retry_after
};

export const CACHE = { MISS: 0, HIT: 1, HIT_STALE: 2, REVALIDATED: 3, MEMO: 4, COMPUTED: 5 };
export const MODE = { QUERY: 0, MUTATE: 1, SUBSCRIBE: 2 };
export const CLASS = { CHEAP: 0, NORMAL: 1, EXPENSIVE: 2 };

const clampUInt = (v) => (Number.isFinite(v) && v > 0 ? Math.floor(v) : 0);
const clampU8 = (v) => (Number.isFinite(v) && v > 0 ? Math.min(255, Math.floor(v)) : 0);

export function frame(type, payload) {
  const body = payload instanceof Uint8Array ? payload : Buffer.from(payload);
  const headLen = varintSize(type) + varintSize(body.length);
  const out = Buffer.allocUnsafe(headLen + body.length);
  let off = writeVarint(out, 0, type);
  off = writeVarint(out, off, body.length);
  out.set(body, off);
  return out;
}

// ── INTENT: what the caller *means*, not just what it asks for ───────────────
// mode | idempotency-key | deadline-ms | declared-cost-ceiling
// | max-shape (how much the answer may cost) | dedup-key
export function encodeIntent({ mode = MODE.QUERY, idem = '', deadlineMs = 30000, costCeiling = 0, maxShape = 0, dedup = '' } = {}) {
  const w = new Writer(64);
  w.u8(clampU8(mode));
  w.bytes(Buffer.from(idem));
  w.varint(clampUInt(deadlineMs));
  w.varint(clampUInt(costCeiling));
  w.varint(clampUInt(maxShape));
  w.bytes(Buffer.from(dedup));
  return frame(F.INTENT, w.finish());
}

export function decodeIntent(buf) {
  const r = new Reader(buf);
  const out = {
    mode: r.u8(),
    idem: r.bytes().toString(),
    deadlineMs: r.varint(),
    costCeiling: r.varint(),
    maxShape: r.varint(),
    dedup: r.bytes().toString(),
  };
  if (!r.done) throw new RangeError('trailing bytes in INTENT frame');
  return out;
}

// ── COST: the economic header. Both directions. ──────────────────────────────
export function encodeCost({ predicted = 0, costClass = CLASS.CHEAP, effortBits = 0, budgetRemaining = 0, value = 0, tokenBudget = 0 } = {}) {
  const w = new Writer(48);
  w.varint(clampUInt(predicted));
  w.u8(clampU8(costClass));
  w.u8(clampU8(effortBits));
  w.varint(clampUInt(budgetRemaining));
  w.varint(clampUInt(value));
  w.varint(clampUInt(tokenBudget));
  return frame(F.COST, w.finish());
}

export function decodeCost(buf) {
  const r = new Reader(buf);
  const out = {
    predicted: r.varint(), costClass: r.u8(), effortBits: r.u8(),
    budgetRemaining: r.varint(), value: r.varint(), tokenBudget: r.varint(),
  };
  if (!r.done) throw new RangeError('trailing bytes in COST frame');
  return out;
}

// ── CAP: bearer token, but scoped and expiring. ──────────────────────────────
export function encodeCap({ token = Buffer.alloc(0), expiresAt = 0, caps = 0, scope = '', delegable = 0 } = {}) {
  const w = new Writer(96);
  w.bytes(token);
  w.varint(clampUInt(expiresAt));
  w.varint(clampUInt(caps));
  w.bytes(Buffer.from(scope));
  w.u8(delegable ? 1 : 0);
  return frame(F.CAP, w.finish());
}

export function decodeCap(buf) {
  const r = new Reader(buf);
  const out = {
    token: Buffer.from(r.bytes()),
    expiresAt: r.varint(),
    caps: r.varint(),
    scope: r.bytes().toString(),
    delegable: r.u8(),
  };
  if (!r.done) throw new RangeError('trailing bytes in CAP frame');
  return out;
}

// ── RESULT: the only way a request ends. Actual cost is always reported. ─────
export function encodeResult({ status = 200, costActual = 0, cache = CACHE.MISS, tokens = 0, memoReuse = 0, wallMs = 0, costAsym = 0, flags = 0 } = {}) {
  const w = new Writer(40);
  w.varint(clampUInt(status));
  w.varint(clampUInt(costActual));
  w.u8(clampU8(cache));
  w.varint(clampUInt(tokens));
  w.varint(clampUInt(memoReuse));
  w.varint(clampUInt(Math.round(wallMs)));
  w.varint(zigzag(Number.isFinite(costAsym) ? Math.round(costAsym) : 0));
  w.u8(clampU8(flags));
  return frame(F.RESULT, w.finish());
}

export function decodeResult(buf) {
  const r = new Reader(buf);
  const status = r.varint(), costActual = r.varint(), cache = r.u8();
  const tokens = r.varint(), memoReuse = r.varint(), wallMs = r.varint();
  const costAsym = unzigzag(r.varint());
  const flags = r.u8();
  if (!r.done) throw new RangeError('trailing bytes in RESULT frame');
  return { status, costActual, cache, tokens, memoReuse, wallMs, costAsym, flags };
}

// ── RATE: server → client budget/burn-rate policy. ───────────────────────────
export function encodeRate({ pressure = 0, budgetRemaining = 0, refillPerSec = 0, blockUntilMs = 0, penaltyMs = 0 } = {}) {
  const w = new Writer(24);
  w.u8(clampU8(pressure));
  w.varint(clampUInt(budgetRemaining));
  w.varint(clampUInt(refillPerSec));
  w.varint(clampUInt(blockUntilMs));
  w.varint(clampUInt(penaltyMs));
  return frame(F.RATE, w.finish());
}

export function decodeRate(buf) {
  const r = new Reader(buf);
  const out = {
    pressure: r.u8(), budgetRemaining: r.varint(), refillPerSec: r.varint(),
    blockUntilMs: r.varint(), penaltyMs: r.varint(),
  };
  if (!r.done) throw new RangeError('trailing bytes in RATE frame');
  return out;
}

export function encodeReject(code, { retryAfterMs = 0, difficulty = 0, detail = '' } = {}) {
  const w = new Writer(32);
  w.u8(clampU8(code));
  w.varint(clampUInt(retryAfterMs));
  w.u8(clampU8(difficulty));
  w.bytes(Buffer.from(detail));
  return frame(F.REJECT, w.finish());
}

export function decodeReject(buf) {
  const r = new Reader(buf);
  const out = { code: r.u8(), retryAfterMs: r.varint(), difficulty: r.u8(), detail: r.bytes().toString() };
  if (!r.done) throw new RangeError('trailing bytes in REJECT frame');
  return out;
}

// ── HELLO: control-stream initial frame (QUIC-stream-native provisioning) ───
export function encodeHello({
  proto = 'h4/1',
  tableVersion = TABLE_VERSION,
  budget = 0,
  windowMs = 10_000,
  sessionKey = Buffer.alloc(0),
  serverId = '',
  agent = '',
} = {}) {
  const w = new Writer(96);
  w.bytes(Buffer.from(proto));
  w.varint(clampUInt(tableVersion));
  w.varint(clampUInt(budget));
  w.varint(clampUInt(windowMs));
  w.bytes(sessionKey instanceof Uint8Array ? sessionKey : Buffer.from(sessionKey, 'base64url'));
  w.bytes(Buffer.from(serverId));
  w.bytes(Buffer.from(agent));
  return frame(F.HELLO, w.finish());
}

export function decodeHello(buf) {
  const r = new Reader(buf);
  const proto = r.bytes().toString();
  const tableVersion = r.varint();
  const budget = r.varint();
  const windowMs = r.varint();
  const sessionKey = Buffer.from(r.bytes());
  const serverId = r.bytes().toString();
  const agent = r.bytes().toString();
  if (!r.done) throw new RangeError('trailing bytes in HELLO frame');
  return { proto, tableVersion, ratePolicy: { budget, windowMs }, sessionKey, serverId, agent };
}

// ── ACCESS: server-side observability log returned to caller (spec §9) ──────
export function encodeAccess({ tier = '', cache = CACHE.MISS, costActual = 0, predicted = 0, wallUs = 0 } = {}) {
  const w = new Writer(32);
  w.bytes(Buffer.from(tier));
  w.u8(clampU8(cache));
  w.varint(clampUInt(costActual));
  w.varint(clampUInt(predicted));
  w.varint(clampUInt(wallUs));
  return frame(F.ACCESS, w.finish());
}

export function decodeAccess(buf) {
  const r = new Reader(buf);
  const out = {
    tier: r.bytes().toString(),
    cache: r.u8(),
    costActual: r.varint(),
    predicted: r.varint(),
    wallUs: r.varint(),
  };
  if (!r.done) throw new RangeError('trailing bytes in ACCESS frame');
  return out;
}

// ── CANCEL / PATH / PING / GOAWAY ───────────────────────────────────────────
export function encodeCancel({ code = 0 } = {}) {
  const w = new Writer(8);
  w.varint(clampUInt(code));
  return frame(F.CANCEL, w.finish());
}
export function decodeCancel(buf) {
  const r = new Reader(buf);
  const out = { code: r.varint() };
  if (!r.done) throw new RangeError('trailing bytes in CANCEL frame');
  return out;
}

export function encodePath({ hint = '' } = {}) {
  const w = new Writer(32);
  w.bytes(Buffer.from(hint));
  return frame(F.PATH, w.finish());
}
export function decodePath(buf) {
  const r = new Reader(buf);
  const out = { hint: r.bytes().toString() };
  if (!r.done) throw new RangeError('trailing bytes in PATH frame');
  return out;
}

export function encodePing({ id = 0 } = {}) {
  const w = new Writer(12);
  w.varint(clampUInt(id));
  return frame(F.PING, w.finish());
}
export function decodePing(buf) {
  const r = new Reader(buf);
  const out = { id: r.varint() };
  if (!r.done) throw new RangeError('trailing bytes in PING frame');
  return out;
}

export function encodeGoaway({ lastStream = 0, reason = 0 } = {}) {
  const w = new Writer(16);
  w.varint(clampUInt(lastStream)).u8(clampU8(reason));
  return frame(F.GOAWAY, w.finish());
}
export function decodeGoaway(buf) {
  const r = new Reader(buf);
  const out = { lastStream: r.varint(), reason: r.u8() };
  if (!r.done) throw new RangeError('trailing bytes in GOAWAY frame');
  return out;
}

export function encodeHeadersFrame(headers) { return frame(F.HEADERS, encodeHeaders(headers)); }
export function decodeHeadersFrame(buf) { return decodeHeaders(buf); }

export function encodeData(buf) { return frame(F.DATA, Buffer.isBuffer(buf) ? buf : Buffer.from(buf)); }

// ── Strict frame iterator: rejects truncated frames instead of clamping ─────
export function* iterFrames(buf) {
  let off = 0;
  while (off < buf.length) {
    const r = new Reader(buf.subarray(off));
    const type = r.varint();
    const len = r.varint();
    const start = off + r.off;
    if (start + len > buf.length) {
      throw new RangeError(`truncated frame payload: need ${len} bytes, have ${buf.length - start}`);
    }
    yield { type, payload: buf.subarray(start, start + len) };
    off = start + len;
  }
}

// ── Streaming frame splitter for chunked QUIC / TCP stream buffers ──────────
export function splitFramesIncremental(buf) {
  const frames = [];
  let off = 0;
  while (off < buf.length) {
    try {
      const r = new Reader(buf.subarray(off));
      const type = r.varint();
      const len = r.varint();
      const start = off + r.off;
      if (start + len > buf.length) break;
      frames.push({ type, payload: buf.subarray(start, start + len) });
      off = start + len;
    } catch {
      // Incomplete varint header at tail of stream chunk: wait for next chunk
      if (buf.length - off < 16) break;
      throw new RangeError('malformed frame header');
    }
  }
  return { frames, rest: buf.subarray(off) };
}
