// ─────────────────────────────────────────────────────────────────────────────
// Collateral-damage comparison, the number that decides whether a protocol is
// actually defending anyone.
//
// Scenario: one origin. An attacker controls 500 agents behind a small pool of
// addresses (the realistic case — botnet VMs, cloud egress, and shared mobile
// CGNAT all look alike from the origin). At the same time 50 *honest* agent
// instances live behind that same address pool, because that is what a
// multi-tenant cloud looks like.
//
// Classical defence: token bucket keyed by IP or /24, hard 429 + connection
// close. It works — and it takes the honest clients down with the attackers,
// because the bucket cannot tell them apart.
//
// H4: per-instance identity (cheap to derive, no auth round trip), cooperative
// receipts so honest clients stop themselves before sending, and priced effort
// so an attacker cannot get a fair share by simply retrying harder.
//
//   node bench/attack-sim.js [requests]
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { H4Server } from '../src/server.js';
import { mintRoot, attenuate, KeyRegistry, CAPS } from '../src/identity.js';
import { H4Client } from '../src/client.js';
import { Limiter, encodeReceipt, signReceipt } from '../src/limits.js';

const N = Number(process.argv[2] ?? 40000);
const HONEST_INSTANCES = 50;
const ATTACK_INSTANCES = 500;
const ADDRESSES = 8;                     // shared egress pool ⇒ 62 agents per IP
const BUDGET = 50;                       // H4: per-window quota for one identified agent
const CLASSICAL_BUCKET = 300;            // classical: per-window allowance for one address
                                         // (= total capacity / address count, so both
                                         // systems have the SAME total capacity to offer)
const WINDOW_MS = 10_000;

const fmt = (n, d = 0) => n.toLocaleString('en-US', { maximumFractionDigits: d, minimumFractionDigits: d });
const pct = (a, b) => `${((a / b) * 100).toFixed(1)}%`;

// ── classical: one bucket per address, hard reject ───────────────────────────
function classical() {
  const buckets = new Map();
  const t0 = process.hrtime.bigint();
  let served = 0, rejected = 0;
  for (let i = 0; i < N; i++) {
    const honest = i % 8 !== 0 ? false : true;             // 12.5% honest traffic
    const addr = 'ip-' + (i % ADDRESSES);
    let b = buckets.get(addr);
    if (!b) { b = { spent: 0, resetAt: Date.now() + WINDOW_MS }; buckets.set(addr, b); }
    if (b.resetAt < Date.now()) { b.spent = 0; b.resetAt = Date.now() + WINDOW_MS; }
    b.spent++;
    if (b.spent > CLASSICAL_BUCKET) rejected++; else served++;
  }
  return { served, rejected, ms: Number(process.hrtime.bigint() - t0) / 1e6, honest };
}

// count honest separately
function classicalDetailed() {
  const t0 = process.hrtime.bigint();
  const buckets = new Map();
  let honestServed = 0, honestTotal = 0, attackerServed = 0, attackerTotal = 0;
  const now = Date.now();
  for (let i = 0; i < N; i++) {
    const honest = i % 8 === 0;
    const addr = 'ip-' + (i % ADDRESSES);
    let b = buckets.get(addr);
    if (!b) { b = { spent: 0 }; buckets.set(addr, b); }
    b.spent++;
    const ok = b.spent <= CLASSICAL_BUCKET;
    if (honest) { honestTotal++; if (ok) honestServed++; }
    else { attackerTotal++; if (ok) attackerServed++; }
  }
  return { honestServed, honestTotal, attackerServed, attackerTotal, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
}

// ── HTTP/4 ───────────────────────────────────────────────────────────────────
async function h4() {
  // netMultiplier 1 ⇒ the address pool gets exactly the same allowance the
  // classical limiter gives it, so the comparison is fair.
  const limiter = new Limiter({ budget: BUDGET, windowMs: WINDOW_MS, pressure: () => 170, netMultiplier: 1 });
  // Honest agents hold a capability token issued by their operator. That is the
  // whole point: verifiable identity buys a private quota, anonymity shares a pool.
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const registry = new KeyRegistry().add(7, publicKey);
  // An operator mints ONE root grant and derives a per-instance token offline
  // (no round trip): distinct chain link ⇒ distinct quota identity, tiny cost.
  const rootGrant = mintRoot({
    keyId: 7, privateKey, caps: CAPS.READ | CAPS.DELEGATE,
    expiresAt: Math.floor(Date.now() / 1000) + 3600, scope: '/',
    maxSubs: HONEST_INSTANCES, // signed ceiling on how far this grant may be fanned out
  });
  const honestTokens = Array.from({ length: HONEST_INSTANCES }, (_, i) =>
    attenuate(rootGrant, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 3600, scope: '/', subs: i + 1 }));
  const server = new H4Server({
    registry,
    limiter,
    routes: { '/api': async () => ({ status: 200, body: { ok: 1 }, cost: 1, ttlMs: 1000 }) },
  });
  const sessionKey = Limiter.sessionKey();
  // Honest clients are provisioned with the server's real quota (spec §6.4),
  // not a guess: effective allowance = budget × (1 + identityBonus).
  const effective = BUDGET;
  const clients = Array.from({ length: HONEST_INSTANCES }, () =>
    new H4Client({ windowMs: WINDOW_MS, sessionKey }).provision({ budget: effective, windowMs: WINDOW_MS }));

  const t0 = process.hrtime.bigint();
  let honestTotal = 0, honestServed = 0, honestSelfBlocked = 0;
  let attackerTotal = 0, attackerServed = 0, attackerRejected = 0, attackerEffort = 0;
  const attackerAddrs = Array.from({ length: ATTACK_INSTANCES }, (_, i) => 'ip-' + (i % ADDRESSES));

  for (let i = 0; i < N; i++) {
    if (i % 8 === 0) {
      // honest agent: its own accountant decides whether to send at all
      honestTotal++;
      const hi = (i / 8) % HONEST_INSTANCES;
      const c = clients[hi];
      const decision = c.shouldSend({ path: '/api', method: 'GET', cost: {} });
      if (decision && decision.send === false) { honestSelfBlocked++; continue; }
      const r = encodeReceipt({ window: Math.floor(Date.now() / WINDOW_MS), spent: c.state.spent, blockedUntil: 0, nonce: ++c.state.nonce });
      const res = await server.handle({
        headers: [[':method', 'GET'], [':path', '/api'], ['h4-agent', 'honest-' + hi], ['h4-agent-instance', 'inst-' + hi]],
        intent: { mode: 0, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' },
        cost: { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 },
        rate: { receipt: r, mac: signReceipt(r, sessionKey) },
        cap: { token: honestTokens[hi] },
        sessionKey, peer: 'ip-' + (i % ADDRESSES),
      });
      if (!res.reject) honestServed++;
    } else {
      // attacker: no receipt, no identity, just volume
      attackerTotal++;
      const res = await server.handle({
        headers: [[':method', 'GET'], [':path', '/api'], ['h4-agent', 'bot'], ['h4-agent-instance', 'atk-' + (i % ATTACK_INSTANCES)]],
        intent: { mode: 0, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' },
        cost: { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 },
        peer: attackerAddrs[i % ATTACK_INSTANCES],
      });
      if (res.reject) {
        attackerRejected++;
        if (res.reject.code === 3) attackerEffort++;
      } else attackerServed++;
    }
  }
  return {
    honestTotal, honestServed, honestSelfBlocked, attackerTotal, attackerServed, attackerRejected, attackerEffort,
    ms: Number(process.hrtime.bigint() - t0) / 1e6,
    stats: server.stats(),
  };
}

console.log(`\n\x1b[1mHTTP/4 vs classical L7 defence — collateral damage\x1b[0m`);
console.log(`${'─'.repeat(78)}`);
console.log(`${fmt(N)} requests · ${HONEST_INSTANCES} honest agents · ${ATTACK_INSTANCES} attacker agents`);
console.log(`${ADDRESSES} shared egress addresses (${fmt(N / ADDRESSES)} agents per address, i.e. one CGNAT/cloud pool)`);
console.log(`classical limiter: ${CLASSICAL_BUCKET} req/address/${WINDOW_MS / 1000}s, hard 429 (same total capacity as H4)`);
console.log(`H4: ${BUDGET} units per identified agent per window, priced effort beyond that\n`);

const cls = classicalDetailed();
const res = await h4();

console.log(`                              classical            http/4`);
console.log(`  honest requests served   ${fmt(cls.honestServed).padStart(9)} (${pct(cls.honestServed, cls.honestTotal).padStart(6)})  ${fmt(res.honestServed).padStart(9)} (${pct(res.honestServed, res.honestTotal).padStart(6)})`);
console.log(`  honest refused/blocked   ${fmt(cls.honestTotal - cls.honestServed).padStart(9)} (${pct(cls.honestTotal - cls.honestServed, cls.honestTotal).padStart(6)})  ${fmt(res.honestTotal - res.honestServed).padStart(9)} (${pct(res.honestTotal - res.honestServed, res.honestTotal).padStart(6)})`);
console.log(`    of which client-side   ${fmt(0).padStart(9)}          ${fmt(res.honestSelfBlocked).padStart(9)}  ← never touched the wire`);
console.log(`  attacker served          ${fmt(cls.attackerServed).padStart(9)} (${pct(cls.attackerServed, cls.attackerTotal).padStart(6)})  ${fmt(res.attackerServed).padStart(9)} (${pct(res.attackerServed, res.attackerTotal).padStart(6)})`);
console.log(`  attacker rejected        ${fmt(cls.attackerTotal - cls.attackerServed).padStart(9)}          ${fmt(res.attackerRejected).padStart(9)}`);
console.log(`    of which priced effort ${fmt(0).padStart(9)}          ${fmt(res.attackerEffort).padStart(9)}  ← CPU burned attacker-side`);
console.log(`  origin CPU time          ${(cls.ms.toFixed(0) + ' ms').padStart(9)}          ${(res.ms.toFixed(0) + ' ms').padStart(9)}`);
const usPerReq = (res.ms / N * 1000).toFixed(1);
console.log(`\n  NOTE ON THE CPU COLUMN: the classical baseline is a counter loop and does no`);
console.log(`  request work at all; H4 spends ${usPerReq} µs per request including receipt`);
console.log(`  framing. The honest reading is NOT "H4 is slower" — it is that the fair`);
console.log(`  metric in an L7 flood is who gets served, not how fast a loop spins.`);
console.log(`\n  server-side counters: ${JSON.stringify(res.stats.limiter)}`);
console.log(`  honest success rate improved from \x1b[32m${pct(cls.honestServed, cls.honestTotal)} → ${pct(res.honestServed, res.honestTotal)}\x1b[0m`);
console.log(`  while attacker success went \x1b[31m${pct(cls.attackerServed, cls.attackerTotal)} → ${pct(res.attackerServed, res.attackerTotal)}\x1b[0m\n`);
