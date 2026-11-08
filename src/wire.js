// ─────────────────────────────────────────────────────────────────────────────
// H4 wire adapter — QUIC-aligned reference carrier over TLS 1.3.
//
// Hardened with:
//   * handshakeTimeoutMs (anti-Slowloris pre-HELLO stall guard)
//   * idleTimeoutMs      (socket idle timeout)
//   * maxConcurrentStreams (anti-Rapid-Reset / stream-flood cap)
//   * IPv4-mapped IPv6 peer normalization
//   * Live bidirectional streaming (`MODE.SUBSCRIBE` + mid-stream `F.CANCEL`)
// ─────────────────────────────────────────────────────────────────────────────

import tls from 'node:tls';
import { readVarint, varintSize, writeVarint } from './varint.js';
import { Limiter } from './limits.js';
import { normalizePeerIp } from './server.js';
import {
  iterFrames, F, REJECT, MODE,
  decodeIntent, decodeCost, decodeCap, decodeCancel, decodeHeadersFrame, decodeResult, decodeReject,
  encodeHello, decodeHello, encodeReject, encodeCancel, decodePing,
} from './frames.js';
import { decodeHeaders, TABLE_VERSION } from './headers.js';

export const PROTO = 'h4/1';
export const ALPN_PROTOCOLS = ['h4', 'h4/1'];
export const CLIENT_CONTROL_STREAM = 2;
export const SERVER_CONTROL_STREAM = 3;

/** Streaming QUIC-varint length-prefixed message parser. */
export class MessageParser {
  constructor(onMessage, { maxFrameBytes = 16 * 1024 * 1024, maxBufferBytes = 32 * 1024 * 1024 } = {}) {
    this.buf = Buffer.alloc(0);
    this.onMessage = onMessage;
    this.maxFrameBytes = maxFrameBytes;
    this.maxBufferBytes = maxBufferBytes;
  }

  push(chunk) {
    if (this.buf.length + chunk.length > this.maxBufferBytes) {
      throw new RangeError('receive buffer exceeded maxBufferBytes');
    }
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    while (this.buf.length > 0) {
      let s, l;
      try {
        s = readVarint(this.buf, 0);
        l = readVarint(this.buf, s.size);
      } catch {
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

function hasTerminalFrame(buf) {
  for (const f of iterFrames(buf)) {
    if (f.type === F.RESULT || f.type === F.REJECT) return true;
  }
  return false;
}

/** Build a TLS 1.3 server carrying H4 with ALPN `h4`. */
export function createServer({
  handler,
  tlsOptions = {},
  metadata = {},
  clusterSecret = null,
  maxFrameBytes = 16 * 1024 * 1024,
  handshakeTimeoutMs = 5_000,
  idleTimeoutMs = 60_000,
  maxConcurrentStreams = 256,
  strictAlpn = true,
}) {
  const server = tls.createServer({
    ALPNProtocols: ALPN_PROTOCOLS,
    minVersion: 'TLSv1.3',
    ...tlsOptions,
  }, (socket) => {
    // ALPACA cross-protocol defense: require negotiated ALPN `h4` or `h4/1`
    if (strictAlpn && socket.alpnProtocol !== 'h4' && socket.alpnProtocol !== 'h4/1') {
      socket.destroy();
      return;
    }
    socket.setNoDelay(true);
    const peer = normalizePeerIp(socket.remoteAddress);
    const sessionKey = clusterSecret
      ? Limiter.deriveSessionKey(clusterSecret, peer)
      : Limiter.sessionKey();
    let ready = false;
    const activeStreams = new Map(); // streamId -> AbortController

    if (idleTimeoutMs > 0) {
      socket.setTimeout(idleTimeoutMs, () => socket.destroy());
    }

    let hsTimer = null;
    if (handshakeTimeoutMs > 0) {
      hsTimer = setTimeout(() => {
        if (!ready && !socket.destroyed) socket.destroy();
      }, handshakeTimeoutMs);
      hsTimer.unref?.();
    }

    const abortAllStreams = () => {
      if (hsTimer) { clearTimeout(hsTimer); hsTimer = null; }
      for (const [, ac] of activeStreams) ac.abort('connection-closed');
      activeStreams.clear();
    };

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
          if (hsTimer) { clearTimeout(hsTimer); hsTimer = null; }
          if (!socket.destroyed) socket.write(packMessage(SERVER_CONTROL_STREAM, reply));
        } catch {
          socket.destroy();
        }
        return;
      }

      if (!ready || (streamId & 0x3) !== 0) {
        socket.destroy();
        return;
      }

      // Check if this is a mid-stream F.CANCEL for an in-flight stream
      if (activeStreams.has(streamId)) {
        try {
          for (const f of iterFrames(payload)) {
            if (f.type === F.CANCEL) {
              decodeCancel(f.payload);
              activeStreams.get(streamId)?.abort('client-cancel');
            }
          }
        } catch {
          socket.destroy();
        }
        return;
      }

      // Enforce per-connection maxConcurrentStreams (anti-Rapid-Reset DoS)
      if (activeStreams.size >= maxConcurrentStreams) {
        if (activeStreams.size >= maxConcurrentStreams * 2) {
          socket.destroy();
          return;
        }
        const rej = encodeReject(REJECT.RATE_LIMITED, { retryAfterMs: 100, detail: 'max-concurrent-streams' });
        if (!socket.destroyed) socket.write(packMessage(streamId, rej));
        return;
      }

      const ac = new AbortController();
      activeStreams.set(streamId, ac);

      Promise.resolve().then(async () => {
        try {
          let req;
          try {
            req = decodeRequest(payload, peer);
          } catch (err) {
            const rej = encodeReject(REJECT.MALFORMED, { detail: err.message });
            if (!socket.destroyed) socket.write(packMessage(streamId, rej));
            return;
          }
          req.sessionKey = sessionKey;

          const method = (req.headers.find(([k]) => k === ':method')?.[1] ?? 'GET').toUpperCase();
          if (req.intent?.mode === MODE.SUBSCRIBE || method === 'SUB') {
            await handler.handleStream(req, {
              signal: ac.signal,
              onFrame: (frameBuf) => {
                if (!socket.destroyed) {
                  socket.write(packMessage(streamId, frameBuf));
                }
              },
            });
          } else {
            const res = await handler.handle(req);
            if (!socket.destroyed) {
              socket.write(packMessage(streamId, Buffer.concat(res.frames)));
            }
          }
        } finally {
          activeStreams.delete(streamId);
        }
      }).catch(() => {
        activeStreams.delete(streamId);
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
    socket.on('close', abortAllStreams);
    socket.on('error', () => {
      abortAllStreams();
      socket.destroy();
    });
  });
  return server;
}

/** Client: connect over TLS 1.3 + ALPN `h4`, exchange `F.HELLO`, multiplex unary & streaming calls. */
export async function connect({
  host = '127.0.0.1',
  port,
  tlsOptions = {},
  agent = 'h4-ref-client/0.2',
  maxFrameBytes = 16 * 1024 * 1024,
  connectTimeoutMs = 5_000,
} = {}) {
  const socket = tls.connect({
    host,
    port,
    ALPNProtocols: ALPN_PROTOCOLS,
    servername: 'localhost',
    ...tlsOptions,
  });
  socket.setNoDelay(true);

  const pending = new Map();
  let bidiSeq = 0;
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
    if (!entry) return;

    if (entry.streaming) {
      entry.chunks.push(payload);
      try {
        for (const f of iterFrames(payload)) {
          if (f.type === F.HEADERS && entry.onHeaders) {
            entry.onHeaders(decodeHeadersFrame(f.payload));
          } else if (f.type === F.DATA && entry.onData) {
            entry.onData(Buffer.from(f.payload));
          } else if (f.type === F.RESULT || f.type === F.REJECT) {
            pending.delete(streamId);
            entry.cleanup?.();
            entry.resolve(Buffer.concat(entry.chunks));
            return;
          }
        }
      } catch (e) {
        pending.delete(streamId);
        entry.cleanup?.();
        entry.reject(e);
      }
      return;
    }

    // Unary stream (accumulate if multi-message until RESULT/REJECT)
    if (entry.chunks) {
      entry.chunks.push(payload);
      if (hasTerminalFrame(payload)) {
        pending.delete(streamId);
        entry.resolve(Buffer.concat(entry.chunks));
      }
    } else if (hasTerminalFrame(payload)) {
      pending.delete(streamId);
      entry.resolve(payload);
    } else {
      entry.chunks = [payload];
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

  let connectTimer = null;
  await new Promise((res, rej) => {
    if (connectTimeoutMs > 0) {
      connectTimer = setTimeout(() => {
        const err = new Error('H4 connect timeout');
        socket.destroy(err);
        rej(err);
      }, connectTimeoutMs);
      connectTimer.unref?.();
    }
    socket.once('secureConnect', res);
    socket.once('error', rej);
  });

  const clientHello = encodeHello({ proto: PROTO, tableVersion: TABLE_VERSION, agent });
  socket.write(packMessage(CLIENT_CONTROL_STREAM, clientHello));
  const hs = await handshakeP;
  if (connectTimer) clearTimeout(connectTimer);

  return {
    handshake: hs,
    alpnProtocol: socket.alpnProtocol,
    sessionKey: Buffer.from(hs.sessionKey, 'base64url'),

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
          streaming: false,
          chunks: null,
          resolve: (payload) => resolve({ virtual, payload, streamId }),
          reject,
        });
        socket.write(packMessage(streamId, frames));
      });
    },

    /**
     * Open a live streaming subscription (`MODE.SUBSCRIBE`).
     * Calls `onData(chunk)` as `F.DATA` frames arrive, sends `F.CANCEL` if
     * `signal` aborts, and resolves with `{ payload, streamId, result, reject }`.
     */
    subscribe(frames, { onData = null, onHeaders = null, signal = null } = {}) {
      if (socket.destroyed) {
        return Promise.reject(lastError ?? new Error('H4 connection closed'));
      }
      const streamId = (bidiSeq++) * 4;
      return new Promise((resolve, reject) => {
        const sendCancel = () => {
          if (!socket.destroyed && pending.has(streamId)) {
            socket.write(packMessage(streamId, encodeCancel({ code: 1 })));
          }
        };
        const cleanup = () => {
          if (signal) signal.removeEventListener('abort', sendCancel);
        };
        if (signal) {
          if (signal.aborted) {
            return reject(new Error('Aborted before subscribe'));
          }
          signal.addEventListener('abort', sendCancel, { once: true });
        }
        pending.set(streamId, {
          streaming: true,
          chunks: [],
          onData,
          onHeaders,
          cleanup,
          resolve: (payload) => {
            let resObj = null, rejObj = null;
            for (const f of iterFrames(payload)) {
              if (f.type === F.RESULT) resObj = decodeResult(f.payload);
              else if (f.type === F.REJECT) rejObj = decodeReject(f.payload);
            }
            resolve({ payload, streamId, result: resObj, reject: rejObj });
          },
          reject,
        });
        socket.write(packMessage(streamId, frames));
      });
    },

    cancel(streamId, code = 0) {
      if (!socket.destroyed) {
        socket.write(packMessage(streamId, encodeCancel({ code })));
      }
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
    pass: undefined,
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
    } else if (k === 'h4-pass' && v !== '') {
      req.pass = v;
    }
  }

  if (chunks.length === 1) req.body = chunks[0];
  else if (chunks.length > 1) req.body = Buffer.concat(chunks);
  if (!req.intent) req.intent = { mode: 0, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' };
  if (!req.cost) req.cost = { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 };
  return req;
}
