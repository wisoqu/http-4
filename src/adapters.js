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

import { extractH4Request, unpackH4Response } from './gateway.js';
import { F, REJECT, MODE, CACHE, iterFrames, decodeReject, decodeHeadersFrame, decodeResult } from './frames.js';

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
    const peer = envOrCtx?.remoteAddress ?? rawHeaders['cf-connecting-ip'] ?? 'web-edge';

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
