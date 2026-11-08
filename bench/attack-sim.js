// ─────────────────────────────────────────────────────────────────────────────
// Collateral-damage comparison across three L7 rate-limiting models:
//
//   1. Classical (per-IP):     token bucket keyed by IP, hard 429
//   2. Classical (per-key):    per-API-key bucket (50/win) + per-IP anon bucket (50/IP/win)
//   3. HTTP/4:                 offline-attenuated capability per sub-agent +
//                              client-side cooperative accounting + priced effort
//
// Scenario: one origin. An attacker controls 500 agents behind 8 shared egress
// addresses while 50 honest agent instances share those same 8 addresses
// ((50 + 500) / 8 = 68.75 ≈ 69 agents per IP — realistic CGNAT / cloud egress).
//
//   node bench/attack-sim.js [requests] [--json]
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { H4Server } from '../src/server.js';
import { mintRoot, attenuate, KeyRegistry, CAPS } from '../src/identity.js';
import { H4Client } from '../src/client.js';
import { Limiter } from '../src/limits.js';

const rawArgs = process.argv.slice(2);
const jsonMode = rawArgs.includes('--json');
const numArg = rawArgs.find((a) => !a.startsWith('--'));
const N = Number(numArg ?? 40000);

const HONEST_INSTANCES = 50;
const ATTACK_INSTANCES = 500;
const ADDRESSES = 8;                     // shared egress pool => (50 + 500) / 8 ≈ 69 agents per IP
const BUDGET = 50;                       // per-window quota for one identified agent
const CLASSICAL_BUCKET = 300;            // per-IP classical allowance (= 2,400 total across 8 IPs)
const WINDOW_MS = 10_000;

const fmt = (n, d = 0) => n.toLocaleString('en-US', { maximumFractionDigits: d, minimumFractionDigits: d });
const pctNum = (a, b) => Number(((a / b) * 100).toFixed(1));
const pct = (a, b) => `${((a / b) * 100).toFixed(1)}%`;

// ── 1. Classical (per-IP): one bucket per address, hard 429 ──────────────────
function classicalPerIp(simNow) {
  const t0 = process.hrtime.bigint();
  const buckets = new Map();
  let honestServed = 0, honestTotal = 0, attackerServed = 0, attackerTotal = 0;
  for (let i = 0; i < N; i++) {
    const honest = i % 8 === 0;
    const addr = 'ip-' + (i % ADDRESSES);
    let b = buckets.get(addr);
    if (!b) { b = { spent: 0, resetAt: simNow + WINDOW_MS }; buckets.set(addr, b); }
    if (b.resetAt < simNow) { b.spent = 0; b.resetAt = simNow + WINDOW_MS; }
    b.spent++;
    const ok = b.spent <= CLASSICAL_BUCKET;
    if (honest) { honestTotal++; if (ok) honestServed++; }
    else { attackerTotal++; if (ok) attackerServed++; }
  }
  return {
    honestServed, honestTotal, honestSelfBlocked: 0,
    attackerServed, attackerTotal, attackerRejected: attackerTotal - attackerServed, attackerEffort: 0,
    ms: Number(process.hrtime.bigint() - t0) / 1e6,
  };
}

// ── 2. Classical (per-key): static API-key bucket + per-IP anon fallback ─────
// Isolates how much of the gain comes purely from caller identification vs H4's
// client-side cooperative self-blocking, offline sub-agent attenuation, & PoE.
function classicalPerKey(simNow) {
  const t0 = process.hrtime.bigint();
  const keyBuckets = new Map();
  const anonIpBuckets = new Map();
  let honestServed = 0, honestTotal = 0, attackerServed = 0, attackerTotal = 0;
  for (let i = 0; i < N; i++) {
    const honest = i % 8 === 0;
    if (honest) {
      honestTotal++;
      const keyId = 'api-key-' + ((i / 8) % HONEST_INSTANCES);
      let b = keyBuckets.get(keyId);
      if (!b) { b = { spent: 0, resetAt: simNow + WINDOW_MS }; keyBuckets.set(keyId, b); }
      if (b.resetAt < simNow) { b.spent = 0; b.resetAt = simNow + WINDOW_MS; }
      b.spent++;
      if (b.spent <= BUDGET) honestServed++;
    } else {
      attackerTotal++;
      const addr = 'ip-' + ((i % ATTACK_INSTANCES) % ADDRESSES);
      let b = anonIpBuckets.get(addr);
      if (!b) { b = { spent: 0, resetAt: simNow + WINDOW_MS }; anonIpBuckets.set(addr, b); }
      if (b.resetAt < simNow) { b.spent = 0; b.resetAt = simNow + WINDOW_MS; }
      b.spent++;
      if (b.spent <= BUDGET) attackerServed++;
    }
  }
  return {
    honestServed, honestTotal, honestSelfBlocked: 0,
    attackerServed, attackerTotal, attackerRejected: attackerTotal - attackerServed, attackerEffort: 0,
    ms: Number(process.hrtime.bigint() - t0) / 1e6,
  };
}

// ── 3. HTTP/4 ────────────────────────────────────────────────────────────────
async function h4(simNow) {
  const limiter = new Limiter({ budget: BUDGET, windowMs: WINDOW_MS, pressure: () => 170, netMultiplier: 1 });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const registry = new KeyRegistry().add(7, publicKey);
  const rootGrant = mintRoot({
    keyId: 7, privateKey, caps: CAPS.READ | CAPS.DELEGATE,
    expiresAt: Math.floor(simNow / 1000) + 3600, scope: '/',
    maxSubs: HONEST_INSTANCES,
  });
  const honestTokens = Array.from({ length: HONEST_INSTANCES }, (_, i) =>
    attenuate(rootGrant, { caps: CAPS.READ, expiresAt: Math.floor(simNow / 1000) + 3600, scope: '/', subs: i + 1 }));
  const server = new H4Server({
    registry,
    limiter,
    routes: { '/api': async () => ({ status: 200, body: { ok: 1 }, cost: 1, ttlMs: 1000 }) },
  });
  const sessionKey = Limiter.sessionKey();
  const clients = Array.from({ length: HONEST_INSTANCES }, () =>
    new H4Client({ windowMs: WINDOW_MS, sessionKey }).provision({ budget: BUDGET, windowMs: WINDOW_MS }));

  const t0 = process.hrtime.bigint();
  let honestTotal = 0, honestServed = 0, honestSelfBlocked = 0;
  let attackerTotal = 0, attackerServed = 0, attackerRejected = 0, attackerEffort = 0;
  const attackerAddrs = Array.from({ length: ATTACK_INSTANCES }, (_, i) => 'ip-' + (i % ADDRESSES));

  for (let i = 0; i < N; i++) {
    if (i % 8 === 0) {
      honestTotal++;
      const hi = (i / 8) % HONEST_INSTANCES;
      const c = clients[hi];
      const decision = c.shouldSend({ path: '/api', method: 'GET', cost: {} });
      if (decision && decision.send === false) { honestSelfBlocked++; continue; }
      const { receipt: r, mac } = c._receipt(1);
      const res = await server.handle({
        headers: [[':method', 'GET'], [':path', '/api'], ['h4-agent', 'honest-' + hi], ['h4-agent-instance', 'inst-' + hi]],
        intent: { mode: 0, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' },
        cost: { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 },
        rate: { receipt: r, mac },
        cap: { token: honestTokens[hi] },
        sessionKey, peer: 'ip-' + (i % ADDRESSES),
      }, simNow);
      if (!res.reject) honestServed++;
    } else {
      attackerTotal++;
      const res = await server.handle({
        headers: [[':method', 'GET'], [':path', '/api'], ['h4-agent', 'bot'], ['h4-agent-instance', 'atk-' + (i % ATTACK_INSTANCES)]],
        intent: { mode: 0, idem: '', deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' },
        cost: { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 },
        peer: attackerAddrs[i % ATTACK_INSTANCES],
      }, simNow);
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

const simNow = Math.floor(Date.now() / WINDOW_MS) * WINDOW_MS + 100;
const clsIp = classicalPerIp(simNow);
const clsKey = classicalPerKey(simNow);
const res = await h4(simNow);
const agentsPerAddress = Math.round((HONEST_INSTANCES + ATTACK_INSTANCES) / ADDRESSES);

if (jsonMode) {
  console.log(JSON.stringify({
    requests: N,
    honestInstances: HONEST_INSTANCES,
    attackerInstances: ATTACK_INSTANCES,
    addresses: ADDRESSES,
    agentsPerAddress,
    budgetPerAgent: BUDGET,
    classicalPerIp: {
      honestServed: clsIp.honestServed,
      honestTotal: clsIp.honestTotal,
      honestServedPct: pctNum(clsIp.honestServed, clsIp.honestTotal),
      honestBlockedPct: pctNum(clsIp.honestTotal - clsIp.honestServed, clsIp.honestTotal),
      attackerServed: clsIp.attackerServed,
      attackerTotal: clsIp.attackerTotal,
      attackerServedPct: pctNum(clsIp.attackerServed, clsIp.attackerTotal),
    },
    classicalPerKey: {
      honestServed: clsKey.honestServed,
      honestTotal: clsKey.honestTotal,
      honestServedPct: pctNum(clsKey.honestServed, clsKey.honestTotal),
      honestSelfBlocked: clsKey.honestSelfBlocked,
      attackerServed: clsKey.attackerServed,
      attackerTotal: clsKey.attackerTotal,
      attackerServedPct: pctNum(clsKey.attackerServed, clsKey.attackerTotal),
    },
    http4: {
      honestServed: res.honestServed,
      honestTotal: res.honestTotal,
      honestServedPct: pctNum(res.honestServed, res.honestTotal),
      honestUnservedPct: pctNum(res.honestTotal - res.honestServed, res.honestTotal),
      honestSelfBlocked: res.honestSelfBlocked,
      attackerServed: res.attackerServed,
      attackerTotal: res.attackerTotal,
      attackerServedPct: pctNum(res.attackerServed, res.attackerTotal),
      attackerEffort: res.attackerEffort,
    },
  }, null, 2));
  process.exit(0);
}

console.log(`\n\x1b[1mHTTP/4 vs classical L7 defence — collateral damage\x1b[0m`);
console.log(`${'─'.repeat(88)}`);
console.log(`${fmt(N)} requests · ${HONEST_INSTANCES} honest agents · ${ATTACK_INSTANCES} attacker agents`);
console.log(`${ADDRESSES} shared egress addresses (~${agentsPerAddress} agents / ${fmt(N / ADDRESSES)} req per address, i.e. one CGNAT/cloud pool)`);
console.log(`classical (per-IP):  ${CLASSICAL_BUCKET} req/address/${WINDOW_MS / 1000}s, hard 429`);
console.log(`classical (per-key): ${BUDGET} req/API-key/${WINDOW_MS / 1000}s + ${BUDGET} anon req/address/${WINDOW_MS / 1000}s, hard 429`);
console.log(`HTTP/4:              ${BUDGET} units per offline-attenuated agent + client self-accounting + priced effort\n`);

const col = (n, p) => `${fmt(n).padStart(7)} (${p.padStart(5)})`;

console.log(`                           classical (per-IP)   classical (per-key)            http/4`);
console.log(`  honest requests served      ${col(clsIp.honestServed, pct(clsIp.honestServed, clsIp.honestTotal))}       ${col(clsKey.honestServed, pct(clsKey.honestServed, clsKey.honestTotal))}       ${col(res.honestServed, pct(res.honestServed, res.honestTotal))}`);
console.log(`  honest unserved/blocked     ${col(clsIp.honestTotal - clsIp.honestServed, pct(clsIp.honestTotal - clsIp.honestServed, clsIp.honestTotal))}       ${col(clsKey.honestTotal - clsKey.honestServed, pct(clsKey.honestTotal - clsKey.honestServed, clsKey.honestTotal))}       ${col(res.honestTotal - res.honestServed, pct(res.honestTotal - res.honestServed, res.honestTotal))}`);
console.log(`    of which client-side      ${fmt(0).padStart(7)}               ${fmt(0).padStart(7)}               ${fmt(res.honestSelfBlocked).padStart(7)}  ← never touched wire`);
console.log(`  attacker served             ${col(clsIp.attackerServed, pct(clsIp.attackerServed, clsIp.attackerTotal))}       ${col(clsKey.attackerServed, pct(clsKey.attackerServed, clsIp.attackerTotal))}       ${col(res.attackerServed, pct(res.attackerServed, res.attackerTotal))}`);
console.log(`  attacker rejected           ${fmt(clsIp.attackerRejected).padStart(7)}               ${fmt(clsKey.attackerRejected).padStart(7)}               ${fmt(res.attackerRejected).padStart(7)}`);
console.log(`    of which priced effort    ${fmt(0).padStart(7)}               ${fmt(0).padStart(7)}               ${fmt(res.attackerEffort).padStart(7)}  ← attacker CPU price`);
console.log(`  origin CPU time             ${(clsIp.ms.toFixed(0) + ' ms').padStart(7)}               ${(clsKey.ms.toFixed(0) + ' ms').padStart(7)}               ${(res.ms.toFixed(0) + ' ms').padStart(7)}`);

const usPerReq = (res.ms / (N - res.honestSelfBlocked) * 1000).toFixed(1);
console.log(`\n  NOTES ON READING THIS TABLE HONESTLY:`);
console.log(`  1. Why 50.0% honest served in per-key & HTTP/4: each of the 50 honest agents tries`);
console.log(`     100 requests in one 10s window against a 50-unit quota. In per-key classical, the`);
console.log(`     extra 2,500 requests hit the origin and get 429'd; in HTTP/4, all 2,500 are stopped`);
console.log(`     client-side before touching the network.`);
console.log(`  2. Identification vs protocol: per-key classical also reaches 50.0% honest / 1.1%`);
console.log(`     attacker IF every sub-agent already has a distinct provisioned API key. HTTP/4`);
console.log(`     derives those 50 sub-agent tokens offline from 1 root grant (0 auth-DB lookups)`);
console.log(`     and replaces free 429s with priced effort (${fmt(res.attackerEffort)} challenges).`);
console.log(`  3. Origin CPU: the classical baselines are bare Map counter loops doing zero parsing,`);
console.log(`     crypto, or response framing; H4 runs full frame/header/capability/receipt handling`);
console.log(`     (~${usPerReq} µs per wire request).\n`);
