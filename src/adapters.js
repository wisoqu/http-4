// ─────────────────────────────────────────────────────────────────────────────
// Universal Framework & Edge Runtime Adapters (`http-4/adapters`)
//
//   • `toWebHandler(h4Server)`       → `(req: Request) => Promise<Response>`
//     (Cloudflare Workers, Deno, Bun, Hono, Next.js App Router, Remix)
//   • `toNodeMiddleware(h4Server)`   → `(req, res, next) => void`
//     (Express, Connect, Polka, Fastify middleware, raw `node:http`)
//   • `wrapFetchHandler(webHandler)` → H4Server route handler wrapping an
//     existing WinterCG `(Request) => Promise<Response>` handler
// ─────────────────────────────────────────────────────────────────────────────

import { extractH4Request, unpackH4Response, createGateway } from './gateway.js';
import { F, REJECT, MODE, CACHE, iterFrames, decodeReject, decodeHeadersFrame, decodeResult } from './frames.js';
import { H4Server } from './server.js';
import { KeyRegistry } from './identity.js';
import { Limiter } from './limits.js';
import { H4Cache } from './cache.js';
import { createServer as createWireServer } from './wire.js';

const REJECT_STATUS = {
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

/**
 * Convert an `H4Server` into a standard WinterCG `(request: Request) => Promise<Response>` handler.
 */
export function toWebHandler(h4Server, { altSvc = null, maxBodyBytes = 4 * 1024 * 1024 } = {}) {
  return async function handleWebRequest(request, envOrCtx = {}) {
    const u = new URL(request.url, 'https://localhost');
    const method = (request.method || 'GET').toUpperCase();
    const rawHeaders = Object.fromEntries(request.headers.entries());
    // Peer attribution MUST come from the platform, never from a request header.
    // `rawHeaders` is attacker-controlled: reading `cf-connecting-ip` off it let a
    // caller pick (and rotate) its own aggregate quota bucket. `request.cf` is
    // injected by the Workers runtime and is not client-writable; `remoteAddress`
    // is the explicit operator-supplied override (SECURITY.md §4.3).
    const peer = envOrCtx?.remoteAddress
      ?? request?.cf?.connectingIp
      ?? envOrCtx?.cf?.connectingIp
      ?? 'web-edge';

    let bodyBuf = Buffer.alloc(0);
    if (method !== 'GET' && method !== 'HEAD' && request.body) {
      const ab = await request.arrayBuffer();
      if (ab.byteLength > maxBodyBytes) {
        return new Response(JSON.stringify({ error: 'payload too large' }), {
          status: 413,
          headers: { 'content-type': 'application/json' },
        });
      }
      bodyBuf = Buffer.from(ab);
    }

    const h4Req = extractH4Request(method, u.pathname + u.search, rawHeaders, bodyBuf, peer);
    const wantsSse = (rawHeaders['accept'] ?? '').toLowerCase().includes('text/event-stream');

    if (h4Req.intent.mode === MODE.SUBSCRIBE) {
      let metaResolve;
      const metaP = new Promise((r) => { metaResolve = r; });
      let resolved = false;
      const enc = new TextEncoder();

      const stream = new ReadableStream({
        start(controller) {
          h4Server.handleStream(h4Req, {
            signal: request.signal,
            onFrame(frameBuf) {
              for (const f of iterFrames(frameBuf)) {
                if (f.type === F.REJECT && !resolved) {
                  resolved = true;
                  metaResolve({ reject: decodeReject(f.payload), headers: [] });
                  controller.close();
                } else if (f.type === F.HEADERS && !resolved) {
                  resolved = true;
                  metaResolve({ reject: null, headers: decodeHeadersFrame(f.payload) });
                } else if (f.type === F.DATA) {
                  if (wantsSse) {
                    const text = Buffer.from(f.payload).toString('utf8').replace(/\r?\n$/, '');
                    controller.enqueue(enc.encode(`data: ${text}\n\n`));
                  } else {
                    controller.enqueue(new Uint8Array(f.payload));
                  }
                } else if (f.type === F.RESULT && wantsSse) {
                  const r = decodeResult(f.payload);
                  controller.enqueue(enc.encode(`event: h4-result\ndata: ${JSON.stringify(r)}\n\n`));
                }
              }
            },
          }).then(() => {
            if (!resolved) { resolved = true; metaResolve({ reject: null, headers: [] }); }
            try { controller.close(); } catch { /* ignore */ }
          }).catch((err) => {
            if (!resolved) { resolved = true; metaResolve({ reject: null, headers: [] }); }
            try { controller.error(err); } catch { /* ignore */ }
          });
        },
      });

      const { reject, headers } = await metaP;
      if (reject) return buildRejectWebResponse(reject, altSvc, method);
      const outHdrs = new Headers({
        'content-type': wantsSse ? 'text/event-stream' : 'application/x-ndjson',
        'cache-control': 'no-cache',
      });
      if (altSvc) outHdrs.set('alt-svc', altSvc);
      for (const [k, v] of headers) {
        if (!k.startsWith(':') && k !== 'content-type') outHdrs.set(k, v);
      }
      return new Response(stream, { status: 200, headers: outHdrs });
    }

    const h4Res = await h4Server.handle(h4Req);
    const decoded = unpackH4Response(h4Res.frames);
    if (decoded.reject) return buildRejectWebResponse(decoded.reject, altSvc, method);

    const outHeaders = new Headers();
    if (altSvc) outHeaders.set('alt-svc', altSvc);
    for (const [k, v] of decoded.headers) {
      if (!k.startsWith(':')) outHeaders.set(k, v);
    }
    if (decoded.result) {
      outHeaders.set('h4-cost-actual', String(decoded.result.costActual));
      outHeaders.set('h4-cost-asym', String(decoded.result.costAsym));
      outHeaders.set('h4-cache', CACHE_NAMES[decoded.result.cache] ?? 'miss');
    }
    if (decoded.rate) {
      outHeaders.set('ratelimit-remaining', String(decoded.rate.budgetRemaining));
    }

    const status = decoded.result?.status ?? 200;
    return new Response(method === 'HEAD' ? null : decoded.body, { status, headers: outHeaders });
  };
}

function buildRejectWebResponse(rej, altSvc, method) {
  const status = rej.code === REJECT.DEFERRED && rej.detail === '0rtt-unsafe-mutate'
    ? 425
    : (REJECT_STATUS[rej.code] ?? 400);
  const hdrs = new Headers({
    'content-type': 'application/json',
    'h4-reject-code': String(rej.code),
  });
  if (altSvc) hdrs.set('alt-svc', altSvc);
  if (rej.retryAfterMs > 0) hdrs.set('retry-after', String(Math.max(1, Math.ceil(rej.retryAfterMs / 1000))));
  if (rej.code === REJECT.EFFORT_REQUIRED) {
    hdrs.set('h4-poe-difficulty', String(rej.difficulty));
    hdrs.set('h4-poe-challenge', rej.detail);
  }
  const body = method === 'HEAD' ? null : JSON.stringify(rej);
  return new Response(body, { status, headers: hdrs });
}

/**
 * Express / Connect / Node `http.IncomingMessage` middleware (`(req, res, next)`).
 * If `passThroughUnmatched` is true and no H4 route matches, calls `next()` AFTER
 * enforcing H4 capability, rate-limit, `h4-pass`, and PoE gates!
 */
export function toNodeMiddleware(h4Server, {
  maxBodyBytes = 4 * 1024 * 1024,
  passThroughUnmatched = true,
  altSvc = null,
} = {}) {
  return async function h4Middleware(req, res, next) {
    try {
      const method = (req.method ?? 'GET').toUpperCase();
      const url = req.originalUrl ?? req.url ?? '/';
      const chunks = [];
      let total = 0;
      if (method !== 'GET' && method !== 'HEAD' && req.readable) {
        if (req.body && (Buffer.isBuffer(req.body) || typeof req.body === 'string' || typeof req.body === 'object')) {
          const b = Buffer.isBuffer(req.body)
            ? req.body
            : Buffer.from(typeof req.body === 'string' ? req.body : JSON.stringify(req.body));
          chunks.push(b);
        } else {
          for await (const ch of req) {
            total += ch.length;
            if (total > maxBodyBytes) {
              res.statusCode = 413;
              res.setHeader('content-type', 'application/json');
              res.end('{"error":"payload too large"}');
              return;
            }
            chunks.push(ch);
          }
        }
      }
      const bodyBuf = chunks.length ? Buffer.concat(chunks) : Buffer.alloc(0);
      const h4Req = extractH4Request(method, url, req.headers ?? {}, bodyBuf, req.socket?.remoteAddress ?? 'anon');
      const h4Res = await h4Server.handle(h4Req);
      const decoded = unpackH4Response(h4Res.frames);

      if (decoded.reject) {
        if (passThroughUnmatched && typeof next === 'function' && decoded.reject.code === REJECT.MALFORMED && decoded.reject.detail === 'no route') {
          req.h4 = { admitted: true };
          next();
          return;
        }
        const webRej = buildRejectWebResponse(decoded.reject, altSvc, method);
        res.statusCode = webRej.status;
        for (const [k, v] of webRej.headers.entries()) res.setHeader(k, v);
        const ab = await webRej.arrayBuffer();
        res.end(Buffer.from(ab));
        return;
      }

      if (altSvc) res.setHeader('alt-svc', altSvc);
      for (const [k, v] of decoded.headers) {
        if (!k.startsWith(':')) res.setHeader(k, v);
      }
      if (decoded.result) {
        res.setHeader('h4-cost-actual', String(decoded.result.costActual));
        res.setHeader('h4-cache', CACHE_NAMES[decoded.result.cache] ?? 'miss');
      }
      res.statusCode = decoded.result?.status ?? 200;
      res.end(method === 'HEAD' ? Buffer.alloc(0) : decoded.body);
    } catch (err) {
      if (typeof next === 'function') next(err);
      else {
        res.statusCode = 500;
        res.end('{"error":"internal middleware error"}');
      }
    }
  };
}

/**
 * Wrap any existing WinterCG `(request: Request) => Promise<Response>` handler
 * as an H4Server route handler (inheriting H4 coalescing, capabilities, and cost gates).
 */
export function wrapFetchHandler(fetchHandler, { cost = 2, ttlMs = 0 } = {}) {
  return async function wrappedRoute(ctx) {
    const hdrs = new Headers();
    for (const [k, v] of Object.entries(ctx.headers)) {
      if (!k.startsWith(':')) {
        try { hdrs.set(k, v); } catch { /* ignore */ }
      }
    }
    const init = { method: ctx.method, headers: hdrs };
    if (ctx.method !== 'GET' && ctx.method !== 'HEAD' && ctx.body) {
      init.body = ctx.body;
    }
    const req = new Request(`https://h4.local${ctx.rawPath}`, init);
    const resp = await fetchHandler(req, ctx);
    const ab = await resp.arrayBuffer();
    return {
      status: resp.status,
      type: resp.headers.get('content-type') ?? 'application/json',
      body: Buffer.from(ab),
      cost: Number(resp.headers.get('h4-cost') || cost),
      ttlMs,
    };
  };
}

/**
 * 1-line zero-boilerplate Express / Connect / Fastify / Node `http` shield:
 *   `app.use(h4Shield({ budget: 100, windowMs: 10_000 }))`
 *
 * Enforces H4 anti-smuggling, capability tokens, cooperative receipts, `h4-pass`,
 * C11 Proof-of-Effort, and 0-RTT replay guards WITHOUT consuming the request body
 * stream — so downstream `express.json()`, `multer`, tRPC, or GraphQL work untouched.
 */
export function h4Shield({
  server = null,
  budget = 200,
  windowMs = 10_000,
  pressure = () => 0,
  poeMode = 'sha256',
  passIssuer = null,
  registry = new KeyRegistry(),
  requireCap = false,
  altSvc = null,
} = {}) {
  const h4 = server ?? new H4Server({
    registry,
    requireCap,
    limiter: new Limiter({ budget, windowMs, pressure, poeMode, passIssuer }),
  });

  const middleware = function h4ShieldMiddleware(req, res, next) {
    const method = (req.method ?? 'GET').toUpperCase();
    const url = req.originalUrl ?? req.url ?? '/';
    const h4Req = extractH4Request(method, url, req.headers ?? {}, null, req.socket?.remoteAddress ?? 'anon');
    const adm = h4._admit(h4Req, Date.now());

    if (!adm.ok) {
      const rej = adm.response.reject;
      const webRej = buildRejectWebResponse(rej, altSvc, method);
      res.statusCode = webRej.status;
      for (const [k, v] of webRej.headers.entries()) res.setHeader(k, v);
      webRej.arrayBuffer().then((ab) => res.end(Buffer.from(ab)));
      return;
    }

    if (altSvc) res.setHeader('alt-svc', altSvc);
    res.setHeader('ratelimit-remaining', String(adm.ctx.advertised.budgetRemaining));
    res.setHeader('ratelimit-policy', `${h4.limiter.budget};w=${Math.round(h4.limiter.windowMs / 1000)}`);
    req.h4 = {
      admitted: true,
      identity: adm.ctx.identity,
      subject: adm.ctx.subject,
      predictedCost: adm.ctx.predicted,
      budgetRemaining: adm.ctx.advertised.budgetRemaining,
    };
    if (typeof next === 'function') next();
  };

  middleware.server = h4;
  return middleware;
}

/**
 * 1-line wrapper for Next.js App Router, Cloudflare Workers, Bun, Deno, or Hono:
 *   `export default { fetch: withH4(myFetchHandler, { budget: 200, defaultTtlMs: 5000 }) }`
 */
export function withH4(fetchHandler, {
  budget = 200,
  windowMs = 10_000,
  pressure = () => 0,
  poeMode = 'sha256',
  passIssuer = null,
  defaultTtlMs = 0,
  maxCacheBytes = 32 * 1024 * 1024,
  cost = 2,
  registry = new KeyRegistry(),
  requireCap = false,
  altSvc = null,
} = {}) {
  const h4 = new H4Server({
    registry,
    requireCap,
    limiter: new Limiter({ budget, windowMs, pressure, poeMode, passIssuer }),
    cache: new H4Cache({ defaultTtlMs, maxBytes: maxCacheBytes, pressure }),
    routes: {
      '*': wrapFetchHandler(fetchHandler, { cost, ttlMs: defaultTtlMs }),
    },
  });
  const handler = toWebHandler(h4, { altSvc });
  handler.server = h4;
  return handler;
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
]);

/**
 * Zero-code Reverse-Proxy Sidecar in front of ANY backend (Python FastAPI, vLLM,
 * Ollama, Go, Rust, Ruby, Java).
 *
 * Gives any existing HTTP server singleflight request coalescing (100 duplicate
 * agent retries -> 1 upstream call), capability verification, `h4-pass`, and C11 PoE.
 */
export function createReverseProxy({
  upstream,
  budget = 200,
  windowMs = 10_000,
  pressure = () => 0,
  poeMode = 'sha256',
  passIssuer = null,
  defaultTtlMs = 0,
  requireCap = false,
  registry = new KeyRegistry(),
  altSvcPort = null,
  upstreamFetch = globalThis.fetch,
} = {}) {
  if (!upstream) throw new Error('createReverseProxy requires an `upstream` URL (e.g. http://127.0.0.1:8000)');
  const base = new URL(upstream);

  const h4Server = new H4Server({
    registry,
    requireCap,
    limiter: new Limiter({ budget, windowMs, pressure, poeMode, passIssuer }),
    cache: new H4Cache({ defaultTtlMs, pressure }),
    routes: {
      '*': async (ctx) => {
        const target = new URL(ctx.rawPath, base);
        // Prevent open-proxy host escape if rawPath is malformed
        if (target.origin !== base.origin) {
          return { status: 400, body: { error: 'invalid upstream path' }, cost: 1 };
        }
        const fwdHeaders = new Headers();
        for (const [k, v] of Object.entries(ctx.headers)) {
          if (k.startsWith(':') || HOP_BY_HOP_HEADERS.has(k)) continue;
          try { fwdHeaders.set(k, v); } catch { /* ignore */ }
        }
        // Strip spoofable identity headers, then inject verified H4 identity claims
        fwdHeaders.delete('x-h4-verified-subject');
        fwdHeaders.delete('x-h4-verified-tenant');
        fwdHeaders.delete('x-h4-verified-scope');
        if (ctx.identity) {
          fwdHeaders.set('x-h4-verified-subject', ctx.identity.subject);
          fwdHeaders.set('x-h4-verified-tenant', ctx.identity.tenant || '');
          fwdHeaders.set('x-h4-verified-scope', ctx.identity.scope);
        }

        const init = { method: ctx.method, headers: fwdHeaders, redirect: 'manual' };
        if (ctx.method !== 'GET' && ctx.method !== 'HEAD' && ctx.body) {
          init.body = ctx.body;
        }
        const resp = await upstreamFetch(target, init);
        const ab = await resp.arrayBuffer();
        return {
          status: resp.status,
          type: resp.headers.get('content-type') ?? 'application/json',
          body: Buffer.from(ab),
          cost: Number(resp.headers.get('h4-cost') || 2),
          ttlMs: resp.status < 500 ? defaultTtlMs : 0,
        };
      },
    },
  });

  const httpGateway = createGateway({ handler: h4Server, altSvcPort });
  return {
    h4Server,
    httpGateway,
    createTlsServer(tlsOptions) {
      return createWireServer({ handler: h4Server, tlsOptions });
    },
  };
}
