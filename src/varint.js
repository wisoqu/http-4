// H4 varint — 2-bit prefix, 1/2/4/8 byte forms (QUIC RFC 9000 §16 compatible).
// Rationale: re-implementing integer coding buys nothing; matching QUIC keeps
// the carrier layer bit-compatible so H4 frames can ride a QUIC stream as-is.

export const MAX_VARINT = 0x3fffffffffffffffn; // 2^62 - 1 (RFC 9000 §16)

export function varintSize(v) {
  if (typeof v === 'bigint') {
    if (v < 0n || v > MAX_VARINT) throw new RangeError(`varint out of range: ${v}`);
    if (v < 0x40n) return 1;
    if (v < 0x4000n) return 2;
    if (v < 0x40000000n) return 4;
    return 8;
  }
  if (!Number.isInteger(v) || v < 0 || v > Number.MAX_SAFE_INTEGER) {
    throw new RangeError(`invalid varint: ${v}`);
  }
  if (v < 0x40) return 1;
  if (v < 0x4000) return 2;
  if (v < 0x40000000) return 4;
  return 8;
}

export function writeVarint(buf, off, v) {
  if (typeof v === 'bigint') {
    if (v < 0n || v > MAX_VARINT) throw new RangeError(`varint out of range: ${v}`);
    if (v < 0x40n) { buf[off] = Number(v); return off + 1; }
    if (v < 0x4000n) { buf.writeUInt16BE(Number(v) | 0x4000, off); return off + 2; }
    if (v < 0x40000000n) { buf.writeUInt32BE((Number(v) | 0x80000000) >>> 0, off); return off + 4; }
    buf.writeBigUInt64BE(v | 0xc000000000000000n, off); return off + 8;
  }
  if (!Number.isInteger(v) || v < 0 || v > Number.MAX_SAFE_INTEGER) {
    throw new RangeError(`invalid varint: ${v}`);
  }
  if (v < 0x40) { buf[off] = v; return off + 1; }
  if (v < 0x4000) { buf.writeUInt16BE(v | 0x4000, off); return off + 2; }
  if (v < 0x40000000) { buf.writeUInt32BE((v | 0x80000000) >>> 0, off); return off + 4; }
  buf.writeBigUInt64BE(BigInt(v) | 0xc000000000000000n, off); return off + 8;
}

export function readVarint(buf, off = 0) {
  const len = buf.length;
  if (off < 0 || off >= len) throw new RangeError('truncated varint');
  const b = buf[off];
  const p = b >> 6;
  if (p === 0) return { value: b & 0x3f, size: 1 };
  if (p === 1) {
    if (off + 2 > len) throw new RangeError('truncated 2-byte varint');
    return { value: buf.readUInt16BE(off) & 0x3fff, size: 2 };
  }
  if (p === 2) {
    if (off + 4 > len) throw new RangeError('truncated 4-byte varint');
    return { value: buf.readUInt32BE(off) & 0x3fffffff, size: 4 };
  }
  if (off + 8 > len) throw new RangeError('truncated 8-byte varint');
  const big = buf.readBigUInt64BE(off) & 0x3fffffffffffffffn;
  if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError('varint exceeds MAX_SAFE_INTEGER; use readVarintBig');
  }
  return { value: Number(big), size: 8 };
}

export function readVarintBig(buf, off = 0) {
  const len = buf.length;
  if (off < 0 || off >= len) throw new RangeError('truncated varint');
  const b = buf[off];
  const p = b >> 6;
  if (p === 0) return { value: BigInt(b & 0x3f), size: 1 };
  if (p === 1) {
    if (off + 2 > len) throw new RangeError('truncated 2-byte varint');
    return { value: BigInt(buf.readUInt16BE(off) & 0x3fff), size: 2 };
  }
  if (p === 2) {
    if (off + 4 > len) throw new RangeError('truncated 4-byte varint');
    return { value: BigInt(buf.readUInt32BE(off) & 0x3fffffff), size: 4 };
  }
  if (off + 8 > len) throw new RangeError('truncated 8-byte varint');
  return { value: buf.readBigUInt64BE(off) & 0x3fffffffffffffffn, size: 8 };
}

// Signed varint via zigzag (H4-COST / RESULT carries signed deltas: actual - predicted).
// Supports full safe integer range without 32-bit bitwise sign overflow.
export function zigzag(n) {
  if (!Number.isInteger(n)) throw new RangeError(`zigzag requires integer, got ${n}`);
  if (n >= -0x40000000 && n <= 0x3fffffff) return ((n << 1) ^ (n >> 31)) >>> 0;
  const b = BigInt(n);
  const z = b < 0n ? ((-b) << 1n) - 1n : b << 1n;
  if (z > MAX_VARINT) throw new RangeError('zigzag overflow');
  return z <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(z) : z;
}

export function unzigzag(u) {
  if (typeof u === 'number' && u >= 0 && u <= 0xffffffff && Number.isInteger(u)) {
    return (u >>> 1) ^ -(u & 1);
  }
  const b = BigInt(u);
  if (b < 0n) throw new RangeError('unzigzag requires unsigned integer');
  const v = (b & 1n) ? -((b + 1n) >> 1n) : (b >> 1n);
  return Number(v);
}

export class Writer {
  constructor(size = 1024) { this.buf = Buffer.allocUnsafe(size); this.off = 0; }
  _ensure(n) {
    if (this.off + n <= this.buf.length) return;
    let cap = this.buf.length || 64;
    while (cap < this.off + n) cap *= 2;
    const nb = Buffer.allocUnsafe(cap);
    this.buf.copy(nb, 0, 0, this.off);
    this.buf = nb;
  }
  varint(v) { this._ensure(8); this.off = writeVarint(this.buf, this.off, v); return this; }
  bytes(b) {
    this._ensure(8 + b.length);
    this.off = writeVarint(this.buf, this.off, b.length);
    this.buf.set(b, this.off);
    this.off += b.length;
    return this;
  }
  raw(b) { this._ensure(b.length); this.buf.set(b, this.off); this.off += b.length; return this; }
  u8(v) {
    if (!Number.isInteger(v) || v < 0 || v > 0xff) throw new RangeError(`invalid u8: ${v}`);
    this._ensure(1);
    this.buf[this.off++] = v;
    return this;
  }
  finish() { return this.buf.subarray(0, this.off); }
}

export class Reader {
  constructor(buf) { this.buf = buf; this.off = 0; }
  varint() { const r = readVarint(this.buf, this.off); this.off += r.size; return r.value; }
  bytes() {
    const n = this.varint();
    if (this.off + n > this.buf.length) throw new RangeError('truncated byte field');
    const b = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return b;
  }
  slice(n) {
    if (!Number.isInteger(n) || n < 0 || this.off + n > this.buf.length) {
      throw new RangeError('truncated fixed slice');
    }
    const b = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return b;
  }
  u8() {
    if (this.off >= this.buf.length) throw new RangeError('unexpected EOF reading u8');
    return this.buf[this.off++];
  }
  get remaining() { return this.buf.length - this.off; }
  get done() { return this.off >= this.buf.length; }
}
