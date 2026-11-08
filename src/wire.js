// ─────────────────────────────────────────────────────────────────────────────
// H4 wire adapter — reference carrier.
//
// In production H4 rides QUIC: each request is a bidirectional QUIC stream, and
// the frames below are just what you write into it. QUIC already gives us
// 0-RTT, connection migration, per-stream flow control and congestion control,
// which is exactly why HTTP/4 does not re-specify any of that.
//
// This adapter uses TLS 1.3 over TCP with an explicit stream-id envelope so the
// multiplexing behaviour is *visible and testable* in an environment without a
// UDP stack:
//
//   handshake :  u32 len | JSON {proto, agent, capabilities, sessionKey?}
//   message   :  u16 streamId | u32 len | H4 frames…
//
// Only the envelope is adapter-specific. Every byte after `len` is a real H4
// frame, encoded by src/frames.js, so the semantics layer is carrier-agnostic.
// ─────────────────────────────────────────────────────────────────────────────

import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { Limiter } from './limits.js';
import { iterFrames, F, decodeIntent, decodeCost, decodeCap } from './frames.js';
import { decodeHeaders } from './headers.js';

export const PROTO = 'h4/1';

/** Minimal length-prefixed message reader. Handles coalesced/split segments. */
export class MessageParser {
  constructor(onMessage) { this.buf = Buffer.alloc(0); this.onMessage = onMessage; }
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    for (;;) {
      if (this.buf.length < 6) return;
      const streamId = this.buf.readUInt16BE(0);
      const len = this.buf.readUInt32BE(2);
      if (len > 64 * 1024 * 1024) throw new Error('frame too large');
      if (this.buf.length < 6 + len) return;
      const payload = this.buf.subarray(6, 6 + len);
      this.buf = this.buf.subarray(6 + len);
      this.onMessage(streamId, payload);
    }
  }
}

export const packMessage = (streamId, frames) => {
  const b = Buffer.allocUnsafe(6 + frames.length);
  b.writeUInt16BE(streamId, 0); b.writeUInt32BE(frames.length, 2);
  frames.copy(b, 6);
  return b;
};

/** Build a TLS server carrying H4. `handler` is an H4Server instance. */
export function createServer({ handler, tlsOptions, metadata = {} }) {
  const server = tls.createServer(tlsOptions, (socket) => {
    const sessionKey = Limiter.sessionKey();
    let ready = false;
    let buf = Buffer.alloc(0);

    // Handshake is a plain length-prefixed JSON blob; only AFTER it do we use
    // the stream-id envelope. Mixing the two framings in one parser was a real
    // bug here: the server tried to read a stream id off a handshake message.
    const parser = new MessageParser(async (streamId, payload) => {
      const req = decodeRequest(payload, socket.remoteAddress);
      req.sessionKey = sessionKey;
      const res = await handler.handle(req);
      socket.write(packMessage(streamId, Buffer.concat(res.frames)));
    });

    socket.on('data', (chunk) => {
      try {
        buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
        if (!ready) {
          if (buf.length < 4) return;
          const len = buf.readUInt32BE(0);
          if (buf.length < 4 + len) return;
          const hello = JSON.parse(buf.subarray(4, 4 + len).toString());
          buf = buf.subarray(4 + len);
          socket.write(packRaw(JSON.stringify({
            proto: PROTO,
            sessionKey: sessionKey.toString('base64url'),
            serverId: metadata.serverId ?? 'h4-edge-1',
            // The server provisions the client's quota (spec §6.4) — the client
            // must not have to guess it.
            ratePolicy: { budget: handler.limiter.budget, windowMs: handler.limiter.windowMs },
            agent: hello.agent ?? 'unknown',
          })));
          ready = true;
        }
        if (buf.length) { parser.push(buf); buf = Buffer.alloc(0); }
      } catch (e) {
        socket.destroy();
      }
    });
    socket.on('error', () => socket.destroy());
  });
  return server;
}

function packRaw(str) {
  const b = Buffer.from(str);
  const out = Buffer.allocUnsafe(4 + b.length);
  out.writeUInt32BE(b.length, 0); b.copy(out, 4);
  return out;
}

/** Client: connect, handshake, then multiplex requests over one socket. */
export async function connect({ host = '127.0.0.1', port, tlsOptions = {}, agent = 'h4-ref-client/0.1' } = {}) {
  const socket = tls.connect({ host, port, ...tlsOptions, servername: 'localhost' });
  const pending = new Map();
  let streamSeq = 0;
  let handshake = null;
  let handshakeResolve;
  const handshakeP = new Promise((r) => { handshakeResolve = r; });

  let buf = Buffer.alloc(0);
  socket.on('data', (chunk) => {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    if (!handshake) {
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) return;
      handshake = JSON.parse(buf.subarray(4, 4 + len).toString());
      buf = buf.subarray(4 + len);
      handshakeResolve(handshake);
      // fall through in case a response was coalesced with the handshake
    }
    const p = new MessageParser((streamId, payload) => {
      const cb = pending.get(streamId);
      if (cb) { pending.delete(streamId); cb(payload); }
    });
    if (buf.length) { p.push(buf); buf = Buffer.alloc(0); }
  });

  await new Promise((res, rej) => { socket.once('secureConnect', res); socket.once('error', rej); });
  socket.write(packRaw(JSON.stringify({ proto: PROTO, agent })));
  const hs = await handshakeP;

  return {
    handshake: hs,
    sessionKey: Buffer.from(hs.sessionKey, 'base64url'),
    /**
     * Send one request. `virtual` is what the client's own accountant decided:
     * requests that fail the accountant never touch the socket.
     */
    request(frames, { virtual = null } = {}) {
      if (virtual && virtual.send === false) {
        return Promise.resolve({ virtual, payload: null });
      }
      const streamId = streamSeq++ & 0xffff;
      return new Promise((resolve) => {
        pending.set(streamId, (payload) => resolve({ virtual, payload }));
        socket.write(packMessage(streamId, frames));
      });
    },
    close() { socket.end(); },
    get streamSeq() { return streamSeq; },
    get pendingCount() { return pending.size; },
  };
}

function decodeRequest(framesBuf, peer) {
  const req = { headers: [], intent: undefined, cost: undefined, cap: undefined, body: null, peer };
  const chunks = [];
  for (const f of iterFrames(framesBuf)) {
    switch (f.type) {
      case F.HEADERS: req.headers = decodeHeaders(f.payload); break;
      case F.INTENT: req.intent = decodeIntent(f.payload); break;
      case F.COST: req.cost = decodeCost(f.payload); break;
      case F.CAP: req.cap = decodeCap(f.payload); break;
      case F.DATA: chunks.push(Buffer.from(f.payload)); break;
      default: break;
    }
  }
  if (chunks.length) req.body = Buffer.concat(chunks);
  if (!req.intent) req.intent = { mode: 0, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' };
  if (!req.cost) req.cost = { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 };
  return req;
}

