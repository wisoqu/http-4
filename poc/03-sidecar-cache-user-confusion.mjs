// PoC 3: The flagship 1-command sidecar (`npx http4 proxy --ttl-ms 5000`) caches
// every GET for `ttl-ms` and shares ONE entry across ALL clients.
//
// The cache key (src/server.js _cacheKey) is:
//   hash(method, rawPath, h4-cache-key, accept, tenantTag, maxShape, bodyHash, dedup)
//
// `cookie`, `authorization`, `x-api-key`, `range`, ... are NOT part of the key, and
// upstream `Cache-Control: private/no-store` is never honoured. For an unauthenticated
// caller tenantTag is the constant `anon:` — so two different logged-in users hitting
// GET /api/me in the same TTL window receive the SAME response body.

import http from 'node:http';
import { createReverseProxy } from '../src/adapters.js';

// ---- upstream: a normal app that answers per-user from the Cookie header ------
let upstreamCalls = 0;
const upstream = http.createServer((req, res) => {
  upstreamCalls++;
  const cookie = req.headers.cookie ?? '';
  const user = /user=(\w+)/.exec(cookie)?.[1] ?? 'anonymous';
  res.writeHead(200, {
    'content-type': 'application/json',
    'cache-control': 'private, no-store', // upstream explicitly forbids sharing
  });
  res.end(JSON.stringify({ user, secret: `api-key-of-${user}` }));
});
await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
const upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;

// ---- http4 sidecar, exactly as the README recommends -------------------------
const { httpGateway } = createReverseProxy({ upstream: upstreamUrl, defaultTtlMs: 5_000 });
await new Promise((r) => httpGateway.listen(0, '127.0.0.1', r));
const port = httpGateway.address().port;

const get = (cookie) => fetch(`http://127.0.0.1:${port}/api/me`, { headers: cookie ? { cookie } : {} })
  .then((r) => r.json());

const a = await get('user=alice');
const b = await get('user=bob');   // different user, same path
const c = await get('user=carol');

console.log('alice ->', JSON.stringify(a));
console.log('bob   ->', JSON.stringify(b), b.user === 'bob' ? '(correct)' : '*** LEAK: served alice\'s response ***');
console.log('carol ->', JSON.stringify(c), c.user === 'carol' ? '(correct)' : '*** LEAK: served alice\'s response ***');
console.log(`upstream was actually called ${upstreamCalls} time(s) for 3 distinct users`);

httpGateway.close();
upstream.close();
