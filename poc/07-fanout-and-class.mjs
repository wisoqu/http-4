// PoC 7: (a) POST requests are never cost-classified as MUTATE over the HTTP gateway
//        (b) `maxSubs` on a root grant is purely decorative — nothing counts sub-agents.

import crypto from 'node:crypto';
import { H4Server } from '../src/server.js';
import { Limiter } from '../src/limits.js';
import { KeyRegistry, mintRoot, attenuate, CAPS } from '../src/identity.js';
import { extractH4Request } from '../src/gateway.js';
import { MODE, CLASS } from '../src/frames.js';

// ── (a) ────────────────────────────────────────────────────────────────────
const r = extractH4Request('POST', '/charge', { host: 'x', 'content-length': '2' }, Buffer.from('{}'), '203.0.113.9');
console.log(`[a] gateway classifies POST /charge as mode=${r.intent.mode} (MODE.MUTATE=${MODE.MUTATE})`);

const srv = new H4Server({ routes: {}, limiter: new Limiter() });
const cheapWeight = srv._classify('/charge', 'POST', { mode: MODE.QUERY }, {});
const mutateWeight = srv._classify('/charge', 'POST', { mode: MODE.MUTATE }, {});
const W = { [CLASS.CHEAP]: 1, [CLASS.NORMAL]: 5, [CLASS.EXPENSIVE]: 60 };
console.log(`[a] server weight for that POST        = ${W[cheapWeight]}  (CLASS.NORMAL)`);
console.log(`[a] weight it would get as MODE.MUTATE = ${W[mutateWeight]}  (CLASS.EXPENSIVE)`);
console.log(`[a] -> an attacker gets ${W[mutateWeight] / W[cheapWeight]}x more writes per window than the cost model intends`);

// ── (b) ────────────────────────────────────────────────────────────────────
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const registry = new KeyRegistry();
registry.add(1, publicKey);

const root = mintRoot({
  keyId: 1, privateKey, caps: CAPS.READ | CAPS.DELEGATE,
  expiresAt: Math.floor(Date.now() / 1000) + 3600, scope: '/', maxSubs: 2, delegable: 1,
});

// mint far more distinct sub-agents than maxSubs=2 permits
const subs = [];
for (let i = 0; i < 500; i++) {
  subs.push(attenuate(root, { caps: CAPS.READ, scope: '/', delegable: 0, subs: i + 1 }));
}

const server = new H4Server({
  routes: { 'GET /v1/x': async () => ({ status: 200, body: { ok: 1 }, cost: 1 }) },
  registry,
  limiter: new Limiter({ budget: 200, windowMs: 10_000 }),
});

const now = Date.now();
const subjects = new Set();
let admitted = 0;
for (const tok of subs) {
  const res = await server.handle({
    headers: [[':method', 'GET'], [':path', '/v1/x'], [':scheme', 'https'], ['h4-agent-instance', `i-${Math.random()}`]],
    intent: { mode: MODE.QUERY, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' },
    cost: { predicted: 0, costClass: CLASS.CHEAP, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 },
    cap: { token: tok },
    peer: '203.0.113.9',
    body: null,
  }, now);
  if (!res.reject) admitted++;
  subjects.add(server.limiter.entries.size);
}
console.log(`[b] root grant said maxSubs=2; we minted ${subs.length} live sub-agents`);
console.log(`[b] all ${admitted}/${subs.length} were admitted; distinct limiter buckets created = ${server.limiter.entries.size}`);
console.log(`[b] shared grant ('net') allowance = budget*(1+bonus)*maxSubs = ${server.limiter.budget * 3 * 2},`);
console.log(`    yet each sub-agent ALSO gets its own ${server.limiter.budget * 3}-unit bucket and maxSubs is never counted.`);
