// H4 varint — 2-bit prefix, 1/2/4/8 byte forms (QUIC-compatible, deliberately).
// Rationale: re-implementing integer coding buys nothing; matching QUIC keeps
// the carrier layer bit-compatible so H4 frames can ride a QUIC stream as-is.

export function varintSize(v) {
  if (v < 0x40) return 1;
  if (v < 0x4000) return 2;
  if (v < 0x40000000) return 4;
  return 8;
}

export function writeVarint(buf, off, v) {
  if (v < 0x40) { buf[off] = v; return off + 1; }
  if (v < 0x4000) { buf.writeUInt16BE(v | 0x4000, off); return off + 2; }
  if (v < 0x40000000) { buf.writeUInt32BE((v | 0x80000000) >>> 0, off); return off + 4; }
  buf.writeBigUInt64BE(BigInt(v) | 0xc000000000000000n, off); return off + 8;
}

export function readVarint(buf, off) {
  const b = buf[off];
  const p = b >> 6;
  if (p === 0) return { value: b & 0x3f, size: 1 };
  if (p === 1) return { value: buf.readUInt16BE(off) & 0x3fff, size: 2 };
  if (p === 2) return { value: buf.readUInt32BE(off) & 0x3fffffff, size: 4 };
  return { value: Number(buf.readBigUInt64BE(off) & 0x3fffffffffffffffn), size: 8 };
}

// Signed varint via zigzag (H4-COST carries signed deltas: energy/cpu can be
// reported as a delta against a predicted baseline).
export const zigzag = (n) => (n << 1) ^ (n >> 31);
export const unzigzag = (n) => (n >>> 1) ^ -(n & 1);

export class Writer {
  constructor(size = 1024) { this.buf = Buffer.allocUnsafe(size); this.off = 0; }
  _ensure(n) {
    if (this.off + n <= this.buf.length) return;
    let cap = this.buf.length * 2;
    while (cap < this.off + n) cap *= 2;
    const nb = Buffer.allocUnsafe(cap); this.buf.copy(nb, 0, 0, this.off); this.buf = nb;
  }
  varint(v) { this._ensure(8); this.off = writeVarint(this.buf, this.off, v); return this; }
  bytes(b) { this._ensure(8 + b.length); this.off = writeVarint(this.buf, this.off, b.length); this.buf.set(b, this.off); this.off += b.length; return this; }
  raw(b) { this._ensure(b.length); this.buf.set(b, this.off); this.off += b.length; return this; }
  u8(v) { this._ensure(1); this.buf[this.off++] = v; return this; }
  finish() { return this.buf.subarray(0, this.off); }
}

export class Reader {
  constructor(buf) { this.buf = buf; this.off = 0; }
  varint() { const r = readVarint(this.buf, this.off); this.off += r.size; return r.value; }
  bytes() { const n = this.varint(); const b = this.buf.subarray(this.off, this.off + n); this.off += n; return b; }
  u8() { return this.buf[this.off++]; }
  get done() { return this.off >= this.buf.length; }
}
