// ─────────────────────────────────────────────────────────────────────────────
// H4 gateway (spec §10): HTTP/1.1 + HTTP/2 ↔ HTTP/4 semantic translator.
//
// Why this exists:
//   "Clean-slate protocols get applause and zero deployment." (§10)
//   An origin running H4Server gets request coalescing, capability attenuation,
//   dual-key rate limiting, and cost-ceiling gates *today* for legacy HTTP/1.1
//   and HTTP/2 callers via this edge translator, while advertising `Alt-Svc`
//   so H4-capable agents can upgrade directly.
// ─────────────────────────────────────────────────────────────────────────────

import http from 'node:http';
import http2 from 'node:http2';
import {
  F, REJECT, CLASS, MODE, CACHE,
  iterFrames, decodeResult, decodeRate, decodeCost, decodeHeadersFrame, decodeReject,
} from './frames.js';

const REJECT_TO_HTTP_STATUS = {
  [REJECT.RATE_LIMITED]: 429,
  [REJECT.BUDGET_EXHAUSTED]: 402,
  [REJECT.EFFORT_REQUIRED]: 402,
  [REJECT.CAP_INVALID]: 401,
  [REJECT.CAP_EXPIRED]: 401,
  [REJECT.SCOPE_DENIED]: 403,
  [REJECT.AGENT_UNKNOWN]: 401,
  [REJECT.COST_REFUSED]: 402,
  [REJECT.MALFORMED]: 400,
  [REJECT.DEFERRED]: 503,
};

const CACHE_NAMES = {
  [CACHE.MISS]: 'miss',
  [CACHE.HIT]: 'hit',
  [CACHE.HIT_STALE]: 'stale',
  [CACHE.REVALIDATED]: 'revalidated',
  [CACHE.MEMO]: 'memo',
  [CACHE.COMPUTED]: 'computed',
};

const CLASS_BY_NAME = {
  cheap: CLASS.CHEAP,
  normal: CLASS.NORMAL,
  expensive: CLASS.EXPENSIVE,
};

function extractH4Request(method, url, rawHeaders, bodyBuf, peer) {
  const hdrs = [
    [':method', method],
    [':path', url || '/'],
    [':scheme', 'https'],
  ];

  let capToken = null;
  let idem = '';
  let dedup = '';
  let deadlineMs = 30_000;
  let costCeiling = 0;
  let maxShape = 0;
  let predicted = 0;
  let costClass = CLASS.CHEAP;
  let value = 0;
  let tokenBudget = 0;
  let effortNonce;

  for (const [rawK, rawV] of Object.entries(rawHeaders)) {
    if (rawV === undefined) continue;
    const k = rawK.toLowerCase();
    if (k.startsWith(':')) continue;
    const v = Array.isArray(rawV) ? rawV.join(', ') : String(rawV);

    if (k === 'authorization' && v.toLowerCase().startsWith('bearer ')) {
      capToken = Buffer.from(v.slice(7).trim(), 'base64url');
      continue;
    }
    if (k === 'h4-cap') {
      capToken = Buffer.from(v.trim(), 'base64url');
      continue;
    }
    if (k === 'idempotency-key' || k === 'h4-idem') idem = v;
    else if (k === 'h4-dedup') dedup = v;
    else if (k === 'h4-deadline-ms') deadlineMs = Math.max(0, parseInt(v, 10) || 30_000);
    else if (k === 'h4-cost-ceiling') costCeiling = Math.max(0, parseInt(v, 10) || 0);
    else if (k === 'h4-max-shape') maxShape = Math.max(0, parseInt(v, 10) || 0);
    else if (k === 'h4-predicted') predicted = Math.max(0, parseInt(v, 10) || 0);
    else if (k === 'h4-cost-class') costClass = CLASS_BY_NAME[v.toLowerCase()] ?? CLASS.CHEAP;
    else if (k === 'h4-value') value = Math.max(0, parseInt(v, 10) || 0);
    else if (k === 'h4-token-budget') tokenBudget = Math.max(0, parseInt(v, 10) || 0);
    else if (k === 'h4-effort') {
      const n = Number(v);
      if (Number.isSafeInteger(n) && n >= 0) effortNonce = n;
    }

    hdrs.push([k, v]);
  }

  const mode = method === 'GET' || method === 'HEAD'
    ? MODE.QUERY
    : (rawHeaders['h4-mode'] === 'mutate' ? MODE.MUTATE : MODE.QUERY);

  return {
    headers: hdrs,
    intent: { mode, idem, deadlineMs, costCeiling, maxShape, dedup },
    cost: { predicted, costClass, effortBits: 0, budgetRemaining: 0, value, tokenBudget },
    cap: capToken ? { token: capToken } : null,
    effortNonce,
    body: bodyBuf && bodyBuf.length ? bodyBuf : null,
    peer,
    byteLength: bodyBuf ? bodyBuf.length : 0,
  };
}

function unpackH4Response(resFrames) {
  let result = null, rate = null, cost = null, reject = null, headers = [], body = Buffer.alloc(0);
  const chunks = [];
  for (const f of iterFrames(Buffer.concat(resFrames))) {
    switch (f.type) {
      case F.RESULT: result = decodeResult(f.payload); break;
      case F.RATE: rate = decodeRate(f.payload); break;
      case F.COST: cost = decodeCost(f.payload); break;
      case F.HEADERS: headers = decodeHeadersFrame(f.payload); break;
      case F.REJECT: reject = decodeReject(f.payload); break;
      case F.DATA: chunks.push(f.payload); break;
      default: break;
    }
  }
  if (chunks.length === 1) body = Buffer.from(chunks[0]);
  else if (chunks.length > 1) body = Buffer.concat(chunks);
  return { result, rate, cost, reject, headers, body };
}

function readStreamBody(stream, maxBodyBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    stream.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBodyBytes) {
        reject(Object.assign(new Error('payload too large'), { statusCode: 413 }));
        stream.destroy();
        return;
      }
      chunks.push(chunk);
    });
    stream.on('end', () => resolve(chunks.length ? Buffer.concat(chunks) : Buffer.alloc(0)));
    stream.on('error', reject);
  });
}

async function handleTranslatedRequest({ handler, method, url, headers, bodyStream, peer, altSvc, maxBodyBytes, send }) {
  let bodyBuf;
  try {
    bodyBuf = (method === 'GET' || method === 'HEAD')
      ? Buffer.alloc(0)
      : await readStreamBody(bodyStream, maxBodyBytes);
  } catch (err) {
    const status = err.statusCode ?? 400;
    const msg = Buffer.from(JSON.stringify({ error: err.message }));
    send(status, { 'content-type': 'application/json' }, msg);
    return;
  }

  const h4Req = extractH4Request(method, url, headers, bodyBuf, peer);
  const h4Res = await handler.handle(h4Req);
  const decoded = unpackH4Response(h4Res.frames);
  const outHeaders = {};
  if (altSvc) outHeaders['alt-svc'] = altSvc;

  if (decoded.reject) {
    const status = REJECT_TO_HTTP_STATUS[decoded.reject.code] ?? 400;
    outHeaders['content-type'] = 'application/json';
    outHeaders['h4-reject-code'] = String(decoded.reject.code);
    if (decoded.reject.retryAfterMs > 0) {
      outHeaders['retry-after'] = String(Math.max(1, Math.ceil(decoded.reject.retryAfterMs / 1000)));
    }
    if (decoded.reject.code === REJECT.EFFORT_REQUIRED) {
      outHeaders['h4-poe-difficulty'] = String(decoded.reject.difficulty);
      outHeaders['h4-poe-challenge'] = decoded.reject.detail;
    }
    const payload = Buffer.from(JSON.stringify({
      reject: decoded.reject.code,
      retryAfterMs: decoded.reject.retryAfterMs,
      difficulty: decoded.reject.difficulty,
      detail: decoded.reject.detail,
    }));
    send(status, outHeaders, method === 'HEAD' ? Buffer.alloc(0) : payload);
    return;
  }

  for (const [k, v] of decoded.headers) {
    if (!k.startsWith(':')) outHeaders[k] = v;
  }
  if (decoded.result) {
    outHeaders['h4-cost-actual'] = String(decoded.result.costActual);
    outHeaders['h4-cost-asym'] = String(decoded.result.costAsym);
    outHeaders['h4-cache'] = CACHE_NAMES[decoded.result.cache] ?? 'miss';
    if (decoded.result.tokens) outHeaders['h4-tokens'] = String(decoded.result.tokens);
  }
  if (decoded.cost) {
    outHeaders['h4-cost-predicted'] = String(decoded.cost.predicted);
  }
  if (decoded.rate) {
    outHeaders['ratelimit-remaining'] = String(decoded.rate.budgetRemaining);
    outHeaders['ratelimit-policy'] = `${handler.limiter.budget};w=${Math.round(handler.limiter.windowMs / 1000)}`;
  }

  const status = decoded.result?.status ?? 200;
  send(status, outHeaders, method === 'HEAD' ? Buffer.alloc(0) : decoded.body);
}

/**
 * HTTP/1.1 ↔ HTTP/4 edge gateway.
 */
export function createGateway({ handler, altSvcPort = null, maxBodyBytes = 4 * 1024 * 1024 } = {}) {
  const altSvc = altSvcPort ? `h4=":${altSvcPort}"; ma=86400` : null;
  return http.createServer((req, res) => {
    handleTranslatedRequest({
      handler,
      method: (req.method ?? 'GET').toUpperCase(),
      url: req.url ?? '/',
      headers: req.headers,
      bodyStream: req,
      peer: req.socket?.remoteAddress ?? 'anon',
      altSvc,
      maxBodyBytes,
      send(status, hdrs, body) {
        if (res.writableEnded) return;
        res.writeHead(status, { ...hdrs, 'content-length': Buffer.byteLength(body) });
        res.end(body);
      },
    }).catch(() => {
      if (!res.writableEnded) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end('{"error":"gateway error"}');
      }
    });
  });
}

/**
 * HTTP/2 (+ optional HTTP/1.1 ALPN fallback) ↔ HTTP/4 edge gateway.
 */
export function createH2Gateway({ handler, tlsOptions = null, altSvcPort = null, maxBodyBytes = 4 * 1024 * 1024 } = {}) {
  const altSvc = altSvcPort ? `h4=":${altSvcPort}"; ma=86400` : null;
  const onRequest = (req, res) => {
    const method = (req.headers[':method'] ?? req.method ?? 'GET').toUpperCase();
    const url = req.headers[':path'] ?? req.url ?? '/';
    const peer = req.stream?.session?.socket?.remoteAddress ?? req.socket?.remoteAddress ?? 'anon';
    handleTranslatedRequest({
      handler,
      method,
      url,
      headers: req.headers,
      bodyStream: req,
      peer,
      altSvc,
      maxBodyBytes,
      send(status, hdrs, body) {
        if (res.writableEnded) return;
        res.writeHead(status, hdrs);
        res.end(body);
      },
    }).catch(() => {
      if (!res.writableEnded) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end('{"error":"gateway error"}');
      }
    });
  };

  return tlsOptions
    ? http2.createSecureServer({ ...tlsOptions, allowHTTP1: true }, onRequest)
    : http2.createServer(onRequest);
}
