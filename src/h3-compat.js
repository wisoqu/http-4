// ─────────────────────────────────────────────────────────────────────────────
// RFC 9114 §7.2.8 HTTP/3 Extension Frame Profile (`h3` + H4 semantic frames)
//
// Maps H4 frames onto HTTP/3 stream framing (`type(quic-varint) ‖ len(quic-varint) ‖ payload`):
//   • DATA (0x00 in H3) and HEADERS (0x01 in H3) map directly to RFC 9114 §7.2.1–7.2.2.
//   • H4 semantic frames (INTENT, COST, CAP, RESULT, RATE, CANCEL, REJECT,
//     PATH, ACCESS, PING, GOAWAY, HELLO) map to unallocated extension codes
//     0x42..0x4d, avoiding RFC 9114 reserved frames (0x00..0x0d), GREASE
//     (0x1f*N + 0x21 = 0x21, 0x40, 0x5f, ...), and WebTransport (0x41).
//   • Per RFC 9114 §9, unknown extension frames MUST be ignored by legacy H3
//     intermediaries/endpoints, enabling incremental deployment over HTTP/3.
// ─────────────────────────────────────────────────────────────────────────────

import { Writer, Reader } from './varint.js';
import { F, frame, iterFrames } from './frames.js';

export const H3_EXT_BASE = 0x42;

export const H4_TO_H3_TYPE = new Map([
  [F.DATA,    0x00],
  [F.HEADERS, 0x01],
  [F.INTENT,  0x42],
  [F.COST,    0x43],
  [F.CAP,     0x44],
  [F.RESULT,  0x45],
  [F.RATE,    0x46],
  [F.CANCEL,  0x47],
  [F.REJECT,  0x48],
  [F.PATH,    0x49],
  [F.ACCESS,  0x4a],
  [F.PING,    0x4b],
  [F.GOAWAY,  0x4c],
  [F.HELLO,   0x4d],
]);

export const H3_TO_H4_TYPE = new Map(
  [...H4_TO_H3_TYPE.entries()].map(([h4, h3]) => [h3, h4])
);

export function isGreaseH3FrameType(type) {
  return type >= 0x21 && (type - 0x21) % 0x1f === 0;
}

/**
 * Convert a raw H4 flight buffer (or array of encoded H4 frame buffers) into an
 * RFC 9114 HTTP/3 stream buffer using GREASE-safe extension frame codes.
 */
export function encodeH3CompatFlight(h4FlightOrFrames) {
  const rawBuf = Array.isArray(h4FlightOrFrames)
    ? Buffer.concat(h4FlightOrFrames)
    : h4FlightOrFrames;
  const parts = [];
  let total = 0;
  for (const f of iterFrames(rawBuf)) {
    const h3Type = H4_TO_H3_TYPE.get(f.type);
    if (h3Type === undefined) throw new Error(`unmapped H4 frame type: ${f.type}`);
    const w = new Writer(f.payload.length + 12);
    w.varint(h3Type).bytes(f.payload);
    const chunk = w.finish();
    parts.push(chunk);
    total += chunk.length;
  }
  return Buffer.concat(parts, total);
}

/**
 * Decode an RFC 9114 HTTP/3 stream buffer back into a canonical H4 flight buffer.
 * Per RFC 9114 §9, unknown extension frames and GREASE frames are safely ignored.
 */
export function decodeH3CompatFlight(h3Buf, { maxFrameLen = 16 * 1024 * 1024, maxFrames = 512 } = {}) {
  const r = new Reader(h3Buf);
  const h4Frames = [];
  let count = 0;
  let total = 0;

  while (!r.done) {
    if (++count > maxFrames) throw new RangeError(`H3 flight exceeds maxFrames (${maxFrames})`);
    const h3Type = r.varint();
    const len = r.varint();
    if (len > maxFrameLen) throw new RangeError(`H3 frame payload exceeds maxFrameLen (${len})`);
    const payload = r.slice(len);

    const h4Type = H3_TO_H4_TYPE.get(h3Type);
    if (h4Type === undefined) {
      // RFC 9114 §9: safely ignore unknown extension / GREASE frames
      continue;
    }
    const encoded = frame(h4Type, payload);
    h4Frames.push(encoded);
    total += encoded.length;
  }

  return h4Frames.length === 0 ? Buffer.alloc(0) : Buffer.concat(h4Frames, total);
}
