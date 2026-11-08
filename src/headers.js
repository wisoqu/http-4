// ─────────────────────────────────────────────────────────────────────────────
// H4 header compression: static-dictionary-first, state-free by default.
//
// WHY THIS SHAPE:
//   QPACK needs a dynamic table, which needs HPACK-style synchronisation, which
//   costs memory per connection and creates a decompression-bomb / state-abuse
//   surface. HTTP/4 refuses per-connection header state by default: every
//   header block is independently decodable. The win we take instead is a much
//   smarter STATIC table tuned for what agents actually send — and the table is
//   an on-path policy object (signalled in the handshake), so a network can
//   ship a table v2 without breaking anything.
//
// ENCODING (per field):
//   1xxxxxxx  exact (name,value) static match      → 1 byte (7-bit prefix int)
//   01pxxxxx  name in static table, literal value  → 5-bit prefix int + [pfx] + len + suffix
//   00000000  literal name + literal value
//   value strings use a 1-bit "prefix of a known value" flag (`p`): if the value
//   shares a prefix with a static value (e.g. "https://api.example",
//   "gpt-4o-mini-2024"), we send prefix-id + suffix only. This is where agent
//   traffic compresses best: hundreds of near-identical model/tool strings.
// ─────────────────────────────────────────────────────────────────────────────

import { Writer, Reader } from './varint.js';

export const TABLE_VERSION = 1;

// Order matters: index 0..30 encode name-matches in 1 byte; 0..126 encode exact matches in 1 byte.
export const STATIC_TABLE = [
  // connection / routing
  [':proto', 'h4'], [':proto', 'h3'], [':scheme', 'https'],
  [':method', 'GET'], [':method', 'POST'], [':method', 'HEAD'],
  [':method', 'SUB'],                      // agent subscription (see spec §7)
  [':status', '200'], [':status', '304'], [':status', '429'], [':status', '402'],
  [':status', '401'], [':status', '403'], [':status', '503'],
  // agent identity
  ['h4-agent', ''], ['h4-agent-model', ''], ['h4-agent-instance', ''],
  ['h4-tenant', ''], ['h4-cap', ''], ['h4-delegation', ''],
  // cost / budgeting — the heart of H4-COST
  ['h4-budget', ''], ['h4-budget-remaining', ''], ['h4-cost', ''],
  ['h4-cost-class', 'cheap'], ['h4-cost-class', 'normal'], ['h4-cost-class', 'expensive'],
  ['h4-effort', ''], ['h4-pressure', ''],
  // caching / reuse, minus the URL glue
  ['h4-cache-key', ''], [':path', '/'], ['h4-mut', ''],
  // policy / trust
  ['h4-trust', ''], ['h4-attest', ''], ['h4-rl', ''],
  ['h4-trace', ''], ['h4-ot', ''],
  // classical
  ['content-type', 'application/json'], ['content-type', 'text/html; charset=utf-8'],
  ['accept', 'application/json'], ['accept', '*/*'], ['accept-encoding', 'zstd, br'],
  ['user-agent', ''], ['host', ''], ['etag', ''], ['if-none-match', ''],
  ['cache-control', 'no-store'], ['cache-control', 'max-age=60'],
];

// Values worth a prefix-dictionary slot (agent-era hot strings).
export const VALUE_PREFIXES = [
  '', 'application/', 'text/', 'application/json', 'image/', 'audio/',
  'https://', 'http://', 'https://api.', 'gpt-', 'claude-', 'llama-',
  '/v1/', '/v2/', '/api/', '/v1/chat/', '/v1/messages',
];
const PREFIX_ID = new Map(VALUE_PREFIXES.map((p, i) => [p, i + 1]));

const EXACT = new Map();   // `name\u0000value` → index
const BY_NAME = new Map(); // name → [indices]
for (let i = 0; i < STATIC_TABLE.length; i++) {
  const [n, v] = STATIC_TABLE[i];
  EXACT.set(n + '\u0000' + v, i);
  if (!BY_NAME.has(n)) BY_NAME.set(n, []);
  BY_NAME.get(n).push(i);
}

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

// ── Interning ────────────────────────────────────────────────────────────────
const utf8Cache = new Map();
const utf8 = (s) => {
  let b = utf8Cache.get(s);
  if (b === undefined) {
    if (utf8Cache.size >= 4096) utf8Cache.delete(utf8Cache.keys().next().value);
    b = Buffer.from(enc.encode(s));
    utf8Cache.set(s, b);
  }
  return b;
};
const prefixCache = new Map();

function bestPrefix(value) {
  const hit = prefixCache.get(value);
  if (hit !== undefined) return hit;
  // longest static prefix, skipping the empty one
  let best = 0, bestLen = 0;
  for (const p of VALUE_PREFIXES) {
    if (p.length > bestLen && value.startsWith(p)) { best = PREFIX_ID.get(p); bestLen = p.length; }
  }
  const out = { id: best, len: bestLen };
  if (prefixCache.size >= 8192) prefixCache.delete(prefixCache.keys().next().value);
  prefixCache.set(value, out);
  return out;
}

// Fast ASCII header-name lowercasing: zero allocation when already lowercase.
function lowerHeaderName(name) {
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c >= 65 && c <= 90) return name.toLowerCase();
  }
  return name;
}

// Pre-encode the static table once: names and values that are already bytes
// never touch TextEncoder again.
for (const [n, v] of STATIC_TABLE) { utf8(n); utf8(v); }

// A single reusable buffer: encodeHeaders is synchronous and non-reentrant, so
// pooling removes one allocation per request. The result is copied out because
// callers legitimately hold on to it.
const pool = new Writer(512);

export function encodeHeaders(headers) {
  const w = (pool.off = 0, pool);
  const pairs = Array.isArray(headers) ? headers : Object.entries(headers);
  for (let i = 0; i < pairs.length; i++) {
    const rawName = String(pairs[i][0]);
    const value = pairs[i][1];
    const n = lowerHeaderName(rawName);
    const v = typeof value === 'string' ? value : String(value);
    const exact = EXACT.get(n + '\u0000' + v);
    if (exact !== undefined) {
      if (exact < 0x7f) {
        w.u8(0x80 | exact);
      } else {
        w.u8(0xff).varint(exact - 0x7f);
      }
      continue;
    }
    const ids = BY_NAME.get(n);
    if (ids !== undefined) {
      const idx = ids[0];
      const { id: pfx, len } = bestPrefix(v);
      const flags = 0x40 | (pfx ? 0x20 : 0);
      if (idx < 0x1f) {
        w.u8(flags | idx);
      } else {
        w.u8(flags | 0x1f).varint(idx - 0x1f);
      }
      if (pfx) w.u8(pfx);
      const vb = utf8(v);
      w.bytes(len ? vb.subarray(len) : vb);
    } else {
      const { id: pfx, len } = bestPrefix(v);
      w.u8(pfx ? 0x01 : 0x00);
      w.bytes(utf8(n));
      if (pfx) w.u8(pfx);
      const vb = utf8(v);
      w.bytes(len ? vb.subarray(len) : vb);
    }
  }
  const out = Buffer.allocUnsafe(w.off);
  w.buf.copy(out, 0, 0, w.off);
  return out;
}

export function decodeHeaders(buf, { maxHeaders = 256 } = {}) {
  const r = new Reader(buf);
  const out = [];
  while (!r.done) {
    if (out.length >= maxHeaders) throw new RangeError('too many headers');
    const b = r.u8();
    if (b & 0x80) {
      let idx = b & 0x7f;
      if (idx === 0x7f) idx = 0x7f + r.varint();
      if (idx >= STATIC_TABLE.length) throw new RangeError(`invalid static header index: ${idx}`);
      const e = STATIC_TABLE[idx];
      out.push([e[0], e[1]]);
    } else if (b & 0x40) {
      const hasPrefix = (b & 0x20) !== 0;
      let idx = b & 0x1f;
      if (idx === 0x1f) idx = 0x1f + r.varint();
      if (idx >= STATIC_TABLE.length) throw new RangeError(`invalid static header index: ${idx}`);
      const e = STATIC_TABLE[idx];
      let prefix = '';
      if (hasPrefix) {
        const pid = r.u8();
        if (pid < 1 || pid > VALUE_PREFIXES.length) throw new RangeError(`invalid value prefix id: ${pid}`);
        prefix = VALUE_PREFIXES[pid - 1];
      }
      out.push([e[0], prefix + dec.decode(r.bytes())]);
    } else if (b === 0x00 || b === 0x01) {
      const name = dec.decode(r.bytes());
      let prefix = '';
      if (b === 0x01) {
        const pid = r.u8();
        if (pid < 1 || pid > VALUE_PREFIXES.length) throw new RangeError(`invalid value prefix id: ${pid}`);
        prefix = VALUE_PREFIXES[pid - 1];
      }
      out.push([name, prefix + dec.decode(r.bytes())]);
    } else {
      throw new RangeError(`reserved header encoding tag: 0x${b.toString(16)}`);
    }
  }
  return out;
}

// Convenience: header list → plain object (last wins). Used by non-security
// callers; H4Server validates pseudo-header uniqueness separately.
export const toObject = (list) => Object.fromEntries(list);
