// ─────────────────────────────────────────────────────────────────────────────
// H4 header compression: static-dictionary-first, state-free by default.
//
// ENCODING (per field):
//   1xxxxxxx  exact (name,value) static match      → 1 byte (7-bit prefix int)
//   01pxxxxx  name in static table, literal value  → 5-bit prefix int + [pfx] + len + suffix
//   0000000p  literal name + literal value (p = has value prefix)
// ─────────────────────────────────────────────────────────────────────────────

import { Writer, Reader } from './varint.js';

export const TABLE_VERSION = 1;
export const MAX_HEADER_BYTES = 32 * 1024;

export const STATIC_TABLE = [
  // connection / routing
  [':proto', 'h4'], [':proto', 'h3'], [':scheme', 'https'],
  [':method', 'GET'], [':method', 'POST'], [':method', 'HEAD'],
  [':method', 'SUB'],
  [':status', '200'], [':status', '304'], [':status', '429'], [':status', '402'],
  [':status', '401'], [':status', '403'], [':status', '503'],
  // agent identity
  ['h4-agent', ''], ['h4-agent-model', ''], ['h4-agent-instance', ''],
  ['h4-tenant', ''], ['h4-cap', ''], ['h4-delegation', ''],
  // cost / budgeting
  ['h4-budget', ''], ['h4-budget-remaining', ''], ['h4-cost', ''],
  ['h4-cost-class', 'cheap'], ['h4-cost-class', 'normal'], ['h4-cost-class', 'expensive'],
  ['h4-effort', ''], ['h4-pressure', ''],
  // caching / reuse
  ['h4-cache-key', ''], [':path', '/'], ['h4-mut', ''],
  // policy / trust / passes
  ['h4-trust', ''], ['h4-attest', ''], ['h4-rl', ''],
  ['h4-trace', ''], ['h4-ot', ''],
  // classical
  ['content-type', 'application/json'], ['content-type', 'text/html; charset=utf-8'],
  ['accept', 'application/json'], ['accept', '*/*'], ['accept-encoding', 'zstd, br'],
  ['user-agent', ''], ['host', ''], ['etag', ''], ['if-none-match', ''],
  ['cache-control', 'no-store'], ['cache-control', 'max-age=60'],
  ['h4-pass', ''],
];

export const VALUE_PREFIXES = [
  '', 'application/', 'text/', 'application/json', 'image/', 'audio/',
  'https://', 'http://', 'https://api.', 'gpt-', 'claude-', 'llama-',
  '/v1/', '/v2/', '/api/', '/v1/chat/', '/v1/messages',
];
const PREFIX_ID = new Map(VALUE_PREFIXES.map((p, i) => [p, i + 1]));

const EXACT = new Map();
const BY_NAME = new Map();
for (let i = 0; i < STATIC_TABLE.length; i++) {
  const [n, v] = STATIC_TABLE[i];
  EXACT.set(n + '\u0000' + v, i);
  if (!BY_NAME.has(n)) BY_NAME.set(n, []);
  BY_NAME.get(n).push(i);
}

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

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
  let best = 0, bestLen = 0;
  for (const p of VALUE_PREFIXES) {
    if (p.length > bestLen && value.startsWith(p)) { best = PREFIX_ID.get(p); bestLen = p.length; }
  }
  const out = { id: best, len: bestLen };
  if (prefixCache.size >= 8192) prefixCache.delete(prefixCache.keys().next().value);
  prefixCache.set(value, out);
  return out;
}

// Fast ASCII header-name validation & lowercasing; rejects CRLF/NUL/whitespace smuggling.
function sanitizeHeaderName(name) {
  if (name.length === 0 || name.length > 256) {
    throw new RangeError('invalid header name length');
  }
  let hasUpper = false;
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c <= 32 || c === 127) throw new RangeError('control or whitespace char in header name');
    if (c >= 65 && c <= 90) hasUpper = true;
  }
  return hasUpper ? name.toLowerCase() : name;
}

function assertCleanValue(val) {
  for (let i = 0; i < val.length; i++) {
    const c = val.charCodeAt(i);
    if (c === 0 || c === 10 || c === 13) {
      throw new RangeError('CR/LF/NUL injection in header value');
    }
  }
}

for (const [n, v] of STATIC_TABLE) { utf8(n); utf8(v); }

const pool = new Writer(512);

export function encodeHeaders(headers) {
  const w = (pool.off = 0, pool);
  const pairs = Array.isArray(headers) ? headers : Object.entries(headers);
  for (let i = 0; i < pairs.length; i++) {
    const rawName = String(pairs[i][0]);
    const value = pairs[i][1];
    const n = sanitizeHeaderName(rawName);
    const v = typeof value === 'string' ? value : String(value);
    assertCleanValue(v);

    const exact = EXACT.get(n + '\u0000' + v);
    if (exact !== undefined) {
      if (exact < 0x7f) w.u8(0x80 | exact);
      else w.u8(0xff).varint(exact - 0x7f);
      continue;
    }
    const ids = BY_NAME.get(n);
    if (ids !== undefined) {
      const idx = ids[0];
      const { id: pfx, len } = bestPrefix(v);
      const flags = 0x40 | (pfx ? 0x20 : 0);
      if (idx < 0x1f) w.u8(flags | idx);
      else w.u8(flags | 0x1f).varint(idx - 0x1f);
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
  if (w.off > MAX_HEADER_BYTES) throw new RangeError('encoded header block exceeds MAX_HEADER_BYTES');
  const out = Buffer.allocUnsafe(w.off);
  w.buf.copy(out, 0, 0, w.off);
  return out;
}

export function decodeHeaders(buf, { maxHeaders = 256, maxBytes = MAX_HEADER_BYTES } = {}) {
  if (buf.length > maxBytes) throw new RangeError('header block exceeds maxBytes');
  const r = new Reader(buf);
  const out = [];
  let decodedBytes = 0;
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
      const val = prefix + dec.decode(r.bytes());
      decodedBytes += e[0].length + val.length;
      if (decodedBytes > maxBytes) throw new RangeError('decoded headers exceed maxBytes');
      assertCleanValue(val);
      out.push([e[0], val]);
    } else if (b === 0x00 || b === 0x01) {
      const name = sanitizeHeaderName(dec.decode(r.bytes()));
      let prefix = '';
      if (b === 0x01) {
        const pid = r.u8();
        if (pid < 1 || pid > VALUE_PREFIXES.length) throw new RangeError(`invalid value prefix id: ${pid}`);
        prefix = VALUE_PREFIXES[pid - 1];
      }
      const val = prefix + dec.decode(r.bytes());
      decodedBytes += name.length + val.length;
      if (decodedBytes > maxBytes) throw new RangeError('decoded headers exceed maxBytes');
      assertCleanValue(val);
      out.push([name, val]);
    } else {
      throw new RangeError(`reserved header encoding tag: 0x${b.toString(16)}`);
    }
  }
  return out;
}

export const toObject = (list) => Object.fromEntries(list);
