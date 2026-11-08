// ─────────────────────────────────────────────────────────────────────────────
// H4 5-Minute Integration SDK (`http-4/sdk`)
//
//   • `createH4Fetch(...)` — drop-in Web `fetch(input, init)` client with
//     automatic TLS `h4` connection pooling, `Alt-Svc` upgrade discovery,
//     local budget accounting, zero-CPU `h4-pass` wallet spending, C11 PoE
//     auto-retry (bounded by `maxEffortBits`), and live `ReadableStream` +
//     `AbortSignal` ↔ `F.CANCEL` propagation.
//   • `AgentSession` — 1-line offline macaroon sub-agent delegation + scoped
//     budget tracking (`const sub = agent.delegate({ scope: '/v1/docs', caps: CAPS.READ })`).
// ─────────────────────────────────────────────────────────────────────────────

import { H4Client } from './client.js';
import { connect as wireConnect } from './wire.js';
import { attenuate, CAPS } from './identity.js';
import { REJECT, MODE, CLASS } from './frames.js';

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

function normalizeHeadersList(headersInit) {
  if (!headersInit) return [];
  if (Array.isArray(headersInit)) return headersInit.map(([k, v]) => [String(k).toLowerCase(), String(v)]);
  if (typeof headersInit.entries === 'function') {
    return [...headersInit.entries()].map(([k, v]) => [String(k).toLowerCase(), String(v)]);
  }
  return Object.entries(headersInit).map(([k, v]) => [String(k).toLowerCase(), String(v)]);
}

function buildWebResponse(observed, extra = {}) {
  let status = 200;
  const respHeaders = new Headers();

  for (const [k, v] of observed.headers ?? []) {
    if (k === ':status') status = Number(v) || 200;
    else if (!k.startsWith(':')) {
      try { respHeaders.append(k, v); } catch { /* ignore non-HTTP header names */ }
    }
  }

  let bodyBytes = observed.body ?? Buffer.alloc(0);
  if (observed.reject) {
    status = observed.reject.code === REJECT.DEFERRED && observed.reject.detail === '0rtt-unsafe-mutate'
      ? 425
      : (REJECT_STATUS[observed.reject.code] ?? 400);
    respHeaders.set('content-type', 'application/json');
    respHeaders.set('h4-reject-code', String(observed.reject.code));
    if (observed.reject.retryAfterMs > 0) {
      respHeaders.set('retry-after', String(Math.ceil(observed.reject.retryAfterMs / 1000)));
    }
    bodyBytes = Buffer.from(JSON.stringify(observed.reject));
  } else if (observed.result) {
    status = observed.result.status || status;
    respHeaders.set('h4-cost-actual', String(observed.result.costActual));
    respHeaders.set('h4-cache', String(observed.result.cache));
  }

  const res = new Response(bodyBytes, { status, headers: respHeaders });
  Object.defineProperty(res, 'h4', {
    value: { ...observed, ...extra },
    enumerable: false,
    configurable: true,
  });
  return res;
}

/**
 * Create a Web-standard `fetch(url, init)` function backed by H4.
 *
 * Supports:
 *   - `server`: direct in-process `H4Server` (zero socket overhead for tests/edge)
 *   - `tlsOptions`: TLS options for pooled `h4://host:port` wire connections
 *   - `autoEffort`: automatically spend `h4-pass` or solve PoE up to `maxEffortBits`
 */
export function createH4Fetch({
  server = null,
  tlsOptions = {},
  clientOptions = {},
  defaultCap = null,
  passWallet = [],
  autoEffort = true,
  maxEffortBits = 20,
  fallbackFetch = globalThis.fetch,
} = {}) {
  const client = new H4Client({
    ...clientOptions,
    maxEffortBits,
    passWallet,
  });

  const pool = new Map();       // `host:port` -> Promise<conn>
  const altSvcMap = new Map();  // `origin` -> { host, port }

  async function getWireConn(host, port) {
    const key = `${host}:${port}`;
    let connP = pool.get(key);
    if (!connP) {
      connP = wireConnect({ host, port: Number(port), tlsOptions }).then((conn) => {
        client.sessionKey = conn.sessionKey;
        if (conn.handshake?.ratePolicy?.budget) {
          client.provision(conn.handshake.ratePolicy);
        }
        return conn;
      }).catch((err) => {
        pool.delete(key);
        throw err;
      });
      pool.set(key, connP);
    }
    return connP;
  }

  async function h4Fetch(input, init = {}) {
    const urlStr = typeof input === 'string' ? input : (input instanceof URL ? input.href : input.url);
    const u = new URL(urlStr, 'h4://localhost');
    const method = (init.method ?? (typeof input === 'object' && input.method ? input.method : 'GET')).toUpperCase();
    const pathWithQuery = u.pathname + u.search;
    const hdrs = normalizeHeadersList(init.headers);
    const h4Opts = init.h4 ?? {};

    const capToken = h4Opts.cap ?? defaultCap;
    const capObj = capToken
      ? (capToken instanceof Uint8Array ? { token: Buffer.from(capToken) } : capToken)
      : null;

    const intent = {
      mode: h4Opts.stream || method === 'SUB' ? MODE.SUBSCRIBE : (h4Opts.mode ?? (method === 'POST' || method === 'PUT' || method === 'DELETE' ? MODE.MUTATE : MODE.QUERY)),
      idem: h4Opts.idem ?? '',
      deadlineMs: h4Opts.deadlineMs ?? 30_000,
      costCeiling: h4Opts.costCeiling ?? 0,
      maxShape: h4Opts.maxShape ?? 0,
      dedup: h4Opts.dedup ?? '',
    };
    const cost = {
      predicted: h4Opts.predicted ?? 0,
      costClass: h4Opts.costClass ?? CLASS.CHEAP,
      value: h4Opts.worth ?? h4Opts.value ?? 0,
      tokenBudget: h4Opts.tokenBudget ?? 0,
    };

    // Pre-send local accountant check
    if (h4Opts.checkBudget !== false) {
      const pre = client.shouldSend({ path: u.pathname, method, intent, cost, worth: cost.value });
      if (pre && pre.send === false) {
        const body = Buffer.from(JSON.stringify({ selfBlocked: true, ...pre }));
        const res = new Response(body, {
          status: 429,
          headers: { 'content-type': 'application/json', 'h4-self-blocked': pre.reason },
        });
        Object.defineProperty(res, 'h4', { value: { virtual: pre, reject: null, result: null } });
        return res;
      }
    }

    let rawBody = null;
    if (init.body !== undefined && init.body !== null) {
      if (Buffer.isBuffer(init.body) || init.body instanceof Uint8Array) rawBody = Buffer.from(init.body);
      else if (typeof init.body === 'string') rawBody = Buffer.from(init.body);
      else rawBody = Buffer.from(JSON.stringify(init.body));
    }

    // 1. In-process H4Server mode
    if (server) {
      if (h4Opts.stream || method === 'SUB') {
        return runInProcessStream({ server, client, pathWithQuery, u, method, hdrs, intent, cost, capObj, rawBody, signal: init.signal });
      }
      return runOnceWithAutoEffort(async ({ effortNonce, pass }) => {
        const reqHdrs = [
          [':method', method],
          [':path', pathWithQuery],
          [':scheme', 'https'],
          ...hdrs,
        ];
        if (pass) reqHdrs.push(['h4-pass', pass]);
        const res = await server.handle({
          headers: reqHdrs,
          intent,
          cost,
          cap: capObj,
          effortNonce,
          pass,
          body: rawBody,
          sessionKey: client.sessionKey,
          peer: h4Opts.peer ?? '127.0.0.1',
          earlyData: Boolean(h4Opts.earlyData),
        });
        return client.observe(Buffer.concat(res.frames), { path: u.pathname, method });
      });
    }

    // 2. Wire H4 mode (`h4:` scheme or cached Alt-Svc upgrade)
    const upgraded = altSvcMap.get(u.origin);
    if (u.protocol === 'h4:' || upgraded) {
      const targetHost = upgraded ? upgraded.host : u.hostname;
      const targetPort = upgraded ? upgraded.port : (u.port || 443);
      const conn = await getWireConn(targetHost, targetPort);

      if (h4Opts.stream || method === 'SUB') {
        return runWireStream({ conn, client, pathWithQuery, method, hdrs, intent, cost, capObj, rawBody, signal: init.signal });
      }

      return runOnceWithAutoEffort(async ({ effortNonce, pass }) => {
        const built = client.build({
          path: pathWithQuery, method, headers: hdrs, intent, cost,
          cap: capObj, body: rawBody, effortNonce, pass,
        });
        const { payload } = await conn.request(built.frames);
        return client.observe(payload, { path: u.pathname, method });
      });
    }

    // 3. Classical HTTP/HTTPS fallback with automatic `Alt-Svc: h4=":port"` discovery
    const httpHdrs = new Headers(init.headers);
    if (capObj?.token) httpHdrs.set('h4-cap', Buffer.from(capObj.token).toString('base64url'));
    if (intent.idem) httpHdrs.set('idempotency-key', intent.idem);
    if (intent.costCeiling) httpHdrs.set('h4-cost-ceiling', String(intent.costCeiling));
    if (intent.dedup) httpHdrs.set('h4-dedup', intent.dedup);

    const res = await fallbackFetch(urlStr, { ...init, headers: httpHdrs });
    const altSvc = res.headers.get('alt-svc');
    if (altSvc) {
      const m = altSvc.match(/h4="([^":]*):(\d+)"/);
      if (m) {
        altSvcMap.set(u.origin, { host: m[1] || u.hostname, port: Number(m[2]) });
      }
    }
    return res;
  }

  async function runOnceWithAutoEffort(execAttempt) {
    let obs = await execAttempt({});
    if (autoEffort && obs.reject && obs.reject.code === REJECT.EFFORT_REQUIRED) {
      const pass = client.takePass();
      if (pass) {
        obs = await execAttempt({ pass });
      } else {
        const nonce = client.payEffort(obs.reject);
        if (nonce !== null) {
          obs = await execAttempt({ effortNonce: nonce });
        }
      }
    }
    return buildWebResponse(obs);
  }

  h4Fetch.client = client;
  h4Fetch.close = async () => {
    const conns = await Promise.allSettled([...pool.values()]);
    pool.clear();
    for (const c of conns) {
      if (c.status === 'fulfilled') c.value.close();
    }
  };
  return h4Fetch;
}

function runInProcessStream({ server, client, pathWithQuery, method, hdrs, intent, cost, capObj, rawBody, signal }) {
  let metaResolve;
  const metaP = new Promise((r) => { metaResolve = r; });
  let resolvedMeta = false;

  const stream = new ReadableStream({
    start(controller) {
      const reqHdrs = [[':method', method], [':path', pathWithQuery], [':scheme', 'https'], ...hdrs];
      server.handleStream({
        headers: reqHdrs, intent, cost, cap: capObj, body: rawBody, sessionKey: client.sessionKey, peer: '127.0.0.1',
      }, {
        signal,
        onFrame(frameBuf) {
          const obs = client.observe(frameBuf);
          if (obs.reject) {
            if (!resolvedMeta) { resolvedMeta = true; metaResolve({ reject: obs.reject, headers: [] }); }
            controller.close();
            return;
          }
          if (obs.headers.length && !resolvedMeta) {
            resolvedMeta = true;
            metaResolve({ reject: null, headers: obs.headers });
          }
          if (obs.body.length > 0 && !signal?.aborted) controller.enqueue(new Uint8Array(obs.body));
          if (signal?.aborted) {
            try { controller.close(); } catch { /* ignore */ }
          }
        },
      }).then((finalRes) => {
        if (!resolvedMeta) { resolvedMeta = true; metaResolve({ reject: finalRes.reject ?? null, headers: [] }); }
        try { controller.close(); } catch { /* already closed */ }
      }).catch((err) => {
        if (!resolvedMeta) { resolvedMeta = true; metaResolve({ reject: null, headers: [] }); }
        try { controller.error(err); } catch { /* ignore */ }
      });
    },
  });

  return metaP.then(({ reject, headers }) => {
    if (reject) return buildWebResponse({ reject, headers: [], body: Buffer.alloc(0) });
    const respHeaders = new Headers();
    let status = 200;
    for (const [k, v] of headers) {
      if (k === ':status') status = Number(v) || 200;
      else if (!k.startsWith(':')) respHeaders.append(k, v);
    }
    return new Response(stream, { status, headers: respHeaders });
  });
}

function runWireStream({ conn, client, pathWithQuery, method, hdrs, intent, cost, capObj, rawBody, signal }) {
  const built = client.build({ path: pathWithQuery, method, headers: hdrs, intent, cost, cap: capObj, body: rawBody });
  let metaResolve;
  const metaP = new Promise((r) => { metaResolve = r; });
  let resolvedMeta = false;
  let resultPromise;

  const stream = new ReadableStream({
    start(controller) {
      resultPromise = conn.subscribe(built.frames, {
        signal,
        onHeaders(h) {
          if (!resolvedMeta) { resolvedMeta = true; metaResolve({ headers: h, reject: null }); }
        },
        onData(chunk) {
          if (!resolvedMeta) { resolvedMeta = true; metaResolve({ headers: [], reject: null }); }
          if (!signal?.aborted) controller.enqueue(new Uint8Array(chunk));
        },
      }).then((done) => {
        const obs = client.observe(done.payload);
        if (!resolvedMeta) {
          resolvedMeta = true;
          metaResolve({ headers: obs.headers, reject: obs.reject });
        }
        try { controller.close(); } catch { /* ignore */ }
        return done;
      }).catch((err) => {
        if (!resolvedMeta) { resolvedMeta = true; metaResolve({ headers: [], reject: null }); }
        try { controller.error(err); } catch { /* ignore */ }
      });
    },
  });

  return metaP.then(({ headers, reject }) => {
    if (reject) return buildWebResponse({ reject, headers: [], body: Buffer.alloc(0) });
    const respHeaders = new Headers();
    let status = 200;
    for (const [k, v] of headers) {
      if (k === ':status') status = Number(v) || 200;
      else if (!k.startsWith(':')) respHeaders.append(k, v);
    }
    const res = new Response(stream, { status, headers: respHeaders });
    Object.defineProperty(res, 'h4Done', { value: resultPromise, enumerable: false });
    return res;
  });
}

/**
 * Scoped agent session with 1-line offline macaroon sub-agent delegation.
 */
export class AgentSession {
  constructor({
    token,
    h4Fetch,
    budget = Infinity,
    instanceId = `agent-${Math.random().toString(36).slice(2, 8)}`,
  }) {
    this.token = token instanceof Uint8Array ? Buffer.from(token) : Buffer.from(token, 'base64url');
    this.h4Fetch = h4Fetch;
    this.budget = budget;
    this.spent = 0;
    this.instanceId = instanceId;
    this._subSeq = 0;
  }

  /**
   * Delegate a narrower capability offline (~2 µs raw HMAC, ~7 µs full token
   * parse + claims encode; zero network calls to issuer).
   */
  delegate({
    caps = CAPS.READ,
    scope,
    expiresAt,
    delegable = false,
    budget = Math.floor(this.budget / 2),
    instanceId,
  } = {}) {
    this._subSeq++;
    const childToken = attenuate(this.token, {
      caps,
      scope,
      expiresAt,
      delegable: delegable ? 1 : 0,
      subs: this._subSeq,
    });
    return new AgentSession({
      token: childToken,
      h4Fetch: this.h4Fetch,
      budget: Math.min(budget, Math.max(0, this.budget - this.spent)),
      instanceId: instanceId ?? `${this.instanceId}.sub${this._subSeq}`,
    });
  }

  async fetch(url, init = {}) {
    if (this.spent >= this.budget) {
      throw Object.assign(new Error('AgentSession local budget exhausted'), { code: 'ERR_AGENT_BUDGET' });
    }
    const hdrs = normalizeHeadersList(init.headers);
    hdrs.push(['h4-agent-instance', this.instanceId]);
    const remaining = Number.isFinite(this.budget) ? Math.max(1, this.budget - this.spent) : 0;
    const res = await this.h4Fetch(url, {
      ...init,
      headers: hdrs,
      h4: {
        ...init.h4,
        cap: this.token,
        costCeiling: init.h4?.costCeiling ?? remaining,
      },
    });
    const costActual = res.h4?.result?.costActual ?? Number(res.headers.get('h4-cost-actual') || 0);
    if (costActual > 0) this.spent += costActual;
    return res;
  }

  /** Stream chunks as an async iterator (`for await (const chunk of session.stream(url))`). */
  async *stream(url, init = {}) {
    const res = await this.fetch(url, {
      ...init,
      method: init.method ?? 'SUB',
      h4: { ...init.h4, stream: true },
    });
    if (!res.ok || !res.body) {
      const text = await res.text();
      throw Object.assign(new Error(`H4 stream rejected (${res.status}): ${text}`), { status: res.status, h4: res.h4 });
    }
    const reader = res.body.getReader();
    const onAbort = () => { reader.cancel().catch(() => {}); };
    init.signal?.addEventListener('abort', onAbort, { once: true });
    try {
      while (true) {
        if (init.signal?.aborted) break;
        const { value, done } = await reader.read();
        if (done) break;
        yield Buffer.from(value);
      }
    } finally {
      init.signal?.removeEventListener('abort', onAbort);
      reader.releaseLock();
    }
    if (res.h4Done) {
      const doneInfo = await res.h4Done;
      if (doneInfo?.result?.costActual) this.spent += doneInfo.result.costActual;
    }
  }
}
