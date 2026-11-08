// ─────────────────────────────────────────────────────────────────────────────
// H4 wire adapter — QUIC-aligned reference carrier over TLS 1.3.
//
// In production H4 rides QUIC v1 (RFC 9000):
//   * ALPN token: `h4`
//   * Control stream (QUIC unidirectional stream 2 / 3): carries `F.HELLO` (0x0d)
//   * Request streams (QUIC client-initiated bidi streams 0, 4, 8, 12, …):
//     carry H4 request/response flights directly.
//
// Because Node.js does not expose an unflagged UDP QUIC socket in standard
// sandboxes, this carrier multiplexes QUIC-numbered streams over TLS 1.3 using
// QUIC varint framing:
//
//   envelope : streamId(varint) | length(varint) | H4 frames…
//
// Every byte inside `H4 frames…` — including `F.HELLO` on the control stream —
// is a pure H4 frame from `src/frames.js`. Moving to a native QUIC transport
// removes only the 2-varint stream envelope.
// ─────────────────────────────────────────────────────────────────────────────

import tls from 'node:tls';
import { Writer, readVarint, varintSize, writeVarint } from './varint.js';
import { Limiter } from './limits.js';
import {
  iterFrames, F, REJECT,
  decodeIntent, decodeCost, decodeCap,
  encodeHello, decodeHello, encodeReject, encodePing, decodePing,
} from './frames.js';
import { decodeHeaders, TABLE_VERSION } from './headers.js';

export const PROTO = 'h4/1';
export const ALPN_PROTOCOLS = ['h4', 'h4/1'];
export const CLIENT_CONTROL_STREAM = 2; // RFC 9000 §2.1: client-initiated uni stream 0b10
export const SERVER_CONTROL_STREAM = 3; // RFC 9000 §2.1: server-initiated uni stream 0b11

/** Streaming QUIC-varint length-prefixed message parser. Handles split & coalesced TLS records. */
export class MessageParser {
  constructor(onMessage, { maxFrameBytes = 16 * 1024 * 1024 } = {}) {
    this.buf = Buffer.alloc(0);
    this.onMessage = onMessage;
    this.maxFrameBytes = maxFrameBytes;
  }

  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    while (this.buf.length > 0) {
      let s, l;
      try {
        s = readVarint(this.buf, 0);
        l = readVarint(this.buf, s.size);
      } catch {
        // Need more bytes to finish reading varint header (at most 16 bytes for 2 varints)
        if (this.buf.length < 16) return;
        throw new RangeError('malformed envelope varint');
      }
      const headLen = s.size + l.size;
      if (l.value > this.maxFrameBytes) {
        throw new RangeError(`stream payload too large: ${l.value} > ${this.maxFrameBytes}`);
      }
      if (this.buf.length < headLen + l.value) return;
      const payload = Buffer.from(this.buf.subarray(headLen, headLen + l.value));
      this.buf = this.buf.subarray(headLen + l.value);
      this.onMessage(s.value, payload);
    }
  }
}

export function packMessage(streamId, frames) {
  const body = Buffer.isBuffer(frames) ? frames : Buffer.from(frames);
  const headLen = varintSize(streamId) + varintSize(body.length);
  const out = Buffer.allocUnsafe(headLen + body.length);
  let off = writeVarint(out, 0, streamId);
  off = writeVarint(out, off, body.length);
  body.copy(out, off);
  return out;
}

/** Build a TLS 1.3 server carrying H4 with ALPN `h4`. `handler` is an H4Server instance. */
export function createServer({ handler, tlsOptions = {}, metadata = {}, clusterSecret = null, maxFrameBytes = 16 * 1024 * 1024 }) {
  const server = tls.createServer({
    ALPNProtocols: ALPN_PROTOCOLS,
    minVersion: 'TLSv1.3',
    ...tlsOptions,
  }, (socket) => {
    const peer = socket.remoteAddress ?? 'unknown';
    const sessionKey = clusterSecret
      ? Limiter.deriveSessionKey(clusterSecret, peer)
      : Limiter.sessionKey();
    let ready = false;

    const parser = new MessageParser((streamId, payload) => {
      if (streamId === CLIENT_CONTROL_STREAM) {
        if (ready || payload.length > 16 * 1024) {
          socket.destroy();
          return;
        }
        try {
          const frames = [...iterFrames(payload)];
          if (frames.length !== 1 || frames[0].type !== F.HELLO) {
            socket.destroy();
            return;
          }
          const hello = decodeHello(frames[0].payload);
          const reply = encodeHello({
            proto: PROTO,
            tableVersion: TABLE_VERSION,
            budget: handler.limiter.budget,
            windowMs: handler.limiter.windowMs,
            sessionKey,
            serverId: metadata.serverId ?? 'h4-edge-1',
            agent: hello.agent || 'unknown',
          });
          ready = true;
          if (!socket.destroyed) socket.write(packMessage(SERVER_CONTROL_STREAM, reply));
        } catch {
          socket.destroy();
        }
        return;
      }

      // Request streams (QUIC client-initiated bidirectional streams: streamId % 4 === 0)
      if (!ready || (streamId & 0x3) !== 0) {
        socket.destroy();
        return;
      }

      Promise.resolve().then(async () => {
        let req;
        try {
          req = decodeRequest(payload, peer);
        } catch (err) {
          const rej = encodeReject(REJECT.MALFORMED, { detail: err.message });
          if (!socket.destroyed) socket.write(packMessage(streamId, rej));
          return;
        }
        req.sessionKey = sessionKey;
        const res = await handler.handle(req);
        if (!socket.destroyed) {
          socket.write(packMessage(streamId, Buffer.concat(res.frames)));
        }
      }).catch(() => {
        if (!socket.destroyed) socket.destroy();
      });
    }, { maxFrameBytes });

    socket.on('data', (chunk) => {
      try {
        parser.push(chunk);
      } catch {
        socket.destroy();
      }
    });
    socket.on('error', () => socket.destroy());
  });
  return server;
}

/** Client: connect over TLS 1.3 + ALPN `h4`, exchange `F.HELLO`, multiplex QUIC-numbered streams. */
export async function connect({
  host = '127.0.0.1',
  port,
  tlsOptions = {},
  agent = 'h4-ref-client/0.1',
  maxFrameBytes = 16 * 1024 * 1024,
} = {}) {
  const socket = tls.connect({
    host,
    port,
    ALPNProtocols: ALPN_PROTOCOLS,
    servername: 'localhost',
    ...tlsOptions,
  });

  const pending = new Map();
  let bidiSeq = 0; // QUIC client-initiated bidi streams: 0, 4, 8, 12, …
  let handshake = null;
  let lastError = null;
  let handshakeResolve, handshakeReject;
  const handshakeP = new Promise((res, rej) => {
    handshakeResolve = res;
    handshakeReject = rej;
  });

  const failAll = (err) => {
    lastError = err;
    if (!handshake) handshakeReject(err);
    for (const [, entry] of pending) entry.reject(err);
    pending.clear();
  };

  // Single persistent stream parser for the lifetime of the connection!
  const parser = new MessageParser((streamId, payload) => {
    if (streamId === SERVER_CONTROL_STREAM && !handshake) {
      try {
        const frames = [...iterFrames(payload)];
        if (frames.length !== 1 || frames[0].type !== F.HELLO) {
          throw new Error('expected F.HELLO on server control stream');
        }
        const hello = decodeHello(frames[0].payload);
        handshake = {
          proto: hello.proto,
          tableVersion: hello.tableVersion,
          serverId: hello.serverId,
          ratePolicy: hello.ratePolicy,
          agent: hello.agent,
          alpnProtocol: socket.alpnProtocol || 'h4',
          sessionKey: hello.sessionKey.toString('base64url'),
        };
        handshakeResolve(handshake);
      } catch (e) {
        failAll(e);
        socket.destroy();
      }
      return;
    }
    const entry = pending.get(streamId);
    if (entry) {
      pending.delete(streamId);
      entry.resolve(payload);
    }
  }, { maxFrameBytes });

  socket.on('data', (chunk) => {
    try {
      parser.push(chunk);
    } catch (e) {
      failAll(e);
      socket.destroy();
    }
  });
  socket.on('error', (err) => failAll(err));
  socket.on('close', () => failAll(lastError ?? new Error('H4 connection closed')));

  await new Promise((res, rej) => {
    socket.once('secureConnect', res);
    socket.once('error', rej);
  });

  const clientHello = encodeHello({ proto: PROTO, tableVersion: TABLE_VERSION, agent });
  socket.write(packMessage(CLIENT_CONTROL_STREAM, clientHello));
  const hs = await handshakeP;

  return {
    handshake: hs,
    alpnProtocol: socket.alpnProtocol,
    sessionKey: Buffer.from(hs.sessionKey, 'base64url'),
    /**
     * Send one request on a fresh client-initiated bidirectional stream (0, 4, 8, …).
     */
    request(frames, { virtual = null } = {}) {
      if (virtual && virtual.send === false) {
        return Promise.resolve({ virtual, payload: null });
      }
      if (socket.destroyed) {
        return Promise.reject(lastError ?? new Error('H4 connection closed'));
      }
      const streamId = (bidiSeq++) * 4;
      return new Promise((resolve, reject) => {
        pending.set(streamId, {
          resolve: (payload) => resolve({ virtual, payload, streamId }),
          reject,
        });
        socket.write(packMessage(streamId, frames));
      });
    },
    close() { socket.end(); },
    get streamSeq() { return bidiSeq; },
    get pendingCount() { return pending.size; },
  };
}

export function decodeRequest(framesBuf, peer) {
  const req = {
    headers: null,
    intent: undefined,
    cost: undefined,
    cap: undefined,
    rate: null,
    effortNonce: undefined,
    body: null,
    peer,
    byteLength: framesBuf.length,
  };
  const chunks = [];
  for (const f of iterFrames(framesBuf)) {
    switch (f.type) {
      case F.HEADERS:
        if (req.headers !== null) throw new RangeError('duplicate HEADERS frame');
        req.headers = decodeHeaders(f.payload);
        break;
      case F.INTENT:
        if (req.intent !== undefined) throw new RangeError('duplicate INTENT frame');
        req.intent = decodeIntent(f.payload);
        break;
      case F.COST:
        if (req.cost !== undefined) throw new RangeError('duplicate COST frame');
        req.cost = decodeCost(f.payload);
        break;
      case F.CAP:
        if (req.cap !== undefined) throw new RangeError('duplicate CAP frame');
        req.cap = decodeCap(f.payload);
        break;
      case F.DATA:
        chunks.push(Buffer.from(f.payload));
        break;
      case F.PING:
        decodePing(f.payload);
        break;
      default:
        break;
    }
  }
  if (!req.headers) req.headers = [];

  for (let i = 0; i < req.headers.length; i++) {
    const [k, v] = req.headers[i];
    if (k === 'h4-rl') {
      const comma = v.indexOf(',');
      if (comma > 0) req.rate = { receipt: v.slice(0, comma), mac: v.slice(comma + 1) };
    } else if (k === 'h4-effort' && v !== '') {
      const n = Number(v);
      if (!Number.isSafeInteger(n) || n < 0) throw new RangeError('invalid h4-effort nonce');
      req.effortNonce = n;
    }
  }

  if (chunks.length === 1) req.body = chunks[0];
  else if (chunks.length > 1) req.body = Buffer.concat(chunks);
  if (!req.intent) req.intent = { mode: 0, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' };
  if (!req.cost) req.cost = { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 };
  return req;
}
