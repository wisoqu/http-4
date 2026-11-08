#!/usr/bin/env node
// HTTP/4 end-to-end demo over a real TLS socket.
//
// What it demonstrates, in order:
//   1. handshake advertises a rate policy + session key (provisioning, spec §6.4)
//   2. a request is one flight: HEADERS + INTENT + COST (+ CAP)
//   3. the response always reports actual cost and cache state
//   4. an expensive request is coalesced: 8 callers → 1 computation
//   5. a capability token with a narrow scope is refused before the handler runs
//   6. under pressure the server prices the request (EFFORT_REQUIRED) instead of banning
//
//   node demo.js
//
// TLS is self-signed and generated on the fly; this is a reference carrier for
// the semantics layer, not a production transport.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createServer, connect } from './src/wire.js';
import { H4Server } from './src/server.js';
import { H4Client } from './src/client.js';
import { Limiter } from './src/limits.js';
import { mintRoot, attenuate, KeyRegistry, CAPS } from './src/identity.js';
import * as fr from './src/frames.js';

const tls = (() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'h4-'));
  const key = path.join(dir, 'k.pem'), crt = path.join(dir, 'c.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt,
    '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
})();

const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

// ── issuer + server ─────────────────────────────────────────────────────────
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const registry = new KeyRegistry().add(1, publicKey);
const rootGrant = mintRoot({
  keyId: 1, privateKey, caps: CAPS.READ | CAPS.WRITE | CAPS.DELEGATE,
  expiresAt: Math.floor(Date.now() / 1000) + 3600, scope: '/', maxSubs: 100,
});
const narrowToken = attenuate(rootGrant, {
  caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600, scope: '/v1/items', subs: 1,
});

let computeCalls = 0;
const handler = new H4Server({
  registry,
  limiter: new Limiter({ budget: 200, windowMs: 10_000 }),
  routes: {
    'GET /v1/items': async () => ({ status: 200, body: { items: [1, 2, 3] }, cost: 1, ttlMs: 4000 }),
    'POST /v1/infer': async ({ body }) => {
      computeCalls++;
      await new Promise((r) => setTimeout(r, 60)); // pretend this is a model call
      return { status: 200, body: { ok: true, computed: computeCalls }, cost: 40, tokens: 512, ttlMs: 8000 };
    },
    'GET /v1/admin': async () => ({ status: 200, body: { secret: true }, cost: 1 }),
  },
});

const server = createServer({ handler, tlsOptions: tls, metadata: { serverId: 'h4-demo-edge' } });
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
console.log(`\n${bold('HTTP/4 demo')}  ${dim(`edge listening on 127.0.0.1:${port} (TLS 1.3, reference carrier)`)}`);

// ── 1. handshake ────────────────────────────────────────────────────────────
const conn = await connect({ port, tlsOptions: { rejectUnauthorized: false } });
console.log(`\n${bold('1. handshake')}`);
console.log(`   proto        ${conn.handshake.proto}`);
console.log(`   serverId     ${conn.handshake.serverId}`);
console.log(`   ratePolicy   ${JSON.stringify(conn.handshake.ratePolicy)}  ${dim('← server provisions the client')}`);

// Provisioned from the server's own policy, but with headroom so the demo can
// show the server-side mechanisms first. Client-side self-blocking is shown on
// its own in step 7, with a deliberately under-provisioned client.
const client = new H4Client({ sessionKey: conn.sessionKey, windowMs: 10_000 })
  .provision({ ...conn.handshake.ratePolicy, budget: 2000 });

// ── 2. one-flight request ───────────────────────────────────────────────────
async function call({ path, method = 'GET', cap = null, cost = {}, intent = {}, body = null }) {
  const flight = client.build({
    path, method,
    headers: [['h4-agent', 'demo-agent'], ['h4-agent-instance', 'demo-1'], ['accept', 'application/json']],
    intent, cost, cap, body,
  });
  const decision = client.shouldSend({ path, method, intent, cost });
  if (decision) return { virtual: decision };
  const res = await conn.request(flight.frames, { virtual: decision });
  return client.observe(res.payload);
}

console.log(`\n${bold('2. GET /v1/items')}`);
let res = await call({ path: '/v1/items', cap: { token: narrowToken } });
console.log(`   status       ${res.result.status}`);
console.log(`   body         ${res.body.toString()}`);
console.log(`   cache        ${res.result.cache === fr.CACHE.MISS ? 'miss' : 'hit'}   cost actual ${res.result.costActual}   (predicted ${res.cost.predicted})`);
console.log(`   headers      ${res.headers.length} decoded · response carried RESULT+RATE+COST+HEADERS+DATA`);

console.log(`\n${bold('3. GET /v1/items again (cache + memo)')}`);
res = await call({ path: '/v1/items', cap: { token: narrowToken } });
console.log(`   cache        ${green('hit')}   cost actual ${res.result.costActual}  ${dim('← a hit is priced at 1 unit no matter what the miss cost')}`);

// ── 4. coalescing under a retry storm ───────────────────────────────────────
console.log(`\n${bold('4. eight concurrent POST /v1/infer with the same dedup_key')}`);
const before = computeCalls;
const storm = await Promise.all(Array.from({ length: 8 }, () => call({
  path: '/v1/infer', method: 'POST',
  cap: { token: attenuate(rootGrant, { caps: CAPS.WRITE | CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600, subs: 2 }) },
  intent: { mode: fr.MODE.QUERY, dedup: 'job-42', maxShape: 512 },
  cost: { costClass: fr.CLASS.EXPENSIVE, predicted: 40 },
  body: JSON.stringify({ prompt: 'hello' }),
})));
const computed = computeCalls - before;
const memo = storm.filter((r) => r.result?.cache === fr.CACHE.MEMO).length;
console.log(`   handler runs ${computed === 1 ? green('1') : red(computed)}   memo-reused ${memo}   ${dim('8 requests → 1 model call')}`);
console.log(`   costs seen   ${storm.map((r) => r.result?.costActual ?? '—').join(', ')}`);

// ── 5. scope enforcement before the handler ─────────────────────────────────
console.log(`\n${bold('5. GET /v1/admin with a token scoped to /v1/items')}`);
res = await call({ path: '/v1/admin', cap: { token: narrowToken } });
console.log(`   ${red('rejected')}     code ${res.reject.code} (${res.reject.code === fr.REJECT.SCOPE_DENIED ? 'SCOPE_DENIED' : '?'}) — ${res.reject.detail}`);

// ── 6. the client's own accountant ──────────────────────────────────────────
console.log(`\n${bold('6. an under-provisioned client stops itself before sending')}`);
const greedy = new H4Client({ sessionKey: conn.sessionKey, windowMs: 10_000 }).provision({ budget: 120, windowMs: 10_000 });
let sent = 0, blocked = 0;
for (let i = 0; i < 10; i++) {
  const d = greedy.shouldSend({ path: '/v1/infer', method: 'POST', intent: { mode: fr.MODE.MUTATE }, cost: { costClass: fr.CLASS.EXPENSIVE } });
  if (d) blocked++; else sent++;
}
console.log(`   decided to send   ${sent}`);
console.log(`   blocked itself    ${green(String(blocked))}  ${dim('← these requests never entered the network')}`);
console.log(`   cost avoided      ${greedy.stats.costAvoided} units`);

// ── 7. pressure → price, not ban ────────────────────────────────────────────
console.log(`\n${bold('7. under pressure: priced effort instead of a ban')}`);
handler.limiter.pressure = () => 220;
handler.limiter.budget = 2;
let effort = null;
for (let i = 0; i < 6 && !effort; i++) {
  // distinct dedup key each time, otherwise the cache would short-circuit the limiter
  const r = await call({ path: '/v1/items', cap: null, intent: { dedup: 'k' + i } });
  if (r.reject?.code === fr.REJECT.EFFORT_REQUIRED) effort = r.reject;
}
if (effort) {
  console.log(`   server says  EFFORT_REQUIRED, difficulty ${bold(effort.difficulty)} bits — ${dim('no ban, just a price')}`);
  const challenge = Buffer.from(effort.detail, 'base64url');
  const t0 = process.hrtime.bigint();
  const nonce = client.payEffort({ challenge, bits: effort.difficulty });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`   client payed ${green(`${ms.toFixed(0)} ms`)} of its own CPU (nonce ${nonce})`);
  console.log(`   server paid   ${dim('~2 µs for one SHA-256 verification')}`);
} else {
  console.log(`   ${red('server never priced the request — check the pressure simulation')}`);
}

// ── summary ────────────────────────────────────────────────────────────────
const st = handler.stats();
console.log(`\n${bold('server summary')}`);
console.log(`   requests ${st.requests}  served ${st.served}  rejected ${st.rejected}  coalesced ${st.coalesced}`);
console.log(`   cache    ${JSON.stringify(st.cache)}`);
console.log(`   limiter  ${JSON.stringify(st.limiter)}`);
console.log();

conn.close();
server.close();
