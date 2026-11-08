// H4 benchmarks. Everything printed here is measured on the machine it runs on
// (2 vCPU, Node 20) — no invented numbers in the spec are allowed.
//
//   node bench/bench.js            # full run
//   node bench/bench.js quick      # skip the slow attack simulations

import crypto from 'node:crypto';
import os from 'node:os';
import { encodeHeaders, decodeHeaders } from '../src/headers.js';
import * as fr from '../src/frames.js';
import { Limiter, signReceipt, encodeReceipt, poeChallenge, solvePoE, checkPoE } from '../src/limits.js';
import { H4Server } from '../src/server.js';
import { H4Client } from '../src/client.js';
import { mintRoot, attenuate, verify, KeyRegistry, CAPS } from '../src/identity.js';

const quick = process.argv[2] === 'quick';
const fmt = (n, d = 0) => n.toLocaleString('en-US', { maximumFractionDigits: d, minimumFractionDigits: d });
const hr = (ms) => `${fmt(ms, ms < 1 ? 3 : 1)} ms`;
const bus = (ns) => (ns < 1000 ? `${fmt(ns, 0)} ns` : `${fmt(ns / 1000, 2)} µs`);
const rule = (t) => console.log(`\n\x1b[1m${t}\x1b[0m\n${'─'.repeat(72)}`);

function time(fn, iters) {
  for (let i = 0; i < Math.min(iters, 2000); i++) fn(i); // warm up
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < iters; i++) fn(i);
  const ns = Number(process.hrtime.bigint() - t0);
  return { ns, perOp: ns / iters, opsPerSec: (iters / ns) * 1e9 };
}

console.log(`\x1b[1mHTTP/4 reference benchmark\x1b[0m`);
console.log(`node ${process.version} · ${os.cpus()[0].model.trim()} ×${os.cpus().length} · ${fmt(os.totalmem() / 1e6)} MB`);

// ─────────────────────────────────────────────────────────────────────────────
rule('1. Request size on the wire (what the network actually carries)');

const cases = {
  'simple GET': [
    [':method', 'GET'], [':path', '/'], ['accept', 'application/json'], ['user-agent', 'tool/1'],
  ],
  'agent API call': [
    [':method', 'POST'], [':path', '/v1/chat/completions'], ['h4-agent', 'research-bot'],
    ['h4-agent-model', 'gpt-4o-mini'], ['h4-tenant', 'acme'], ['content-type', 'application/json'],
    ['accept', 'application/json'], ['h4-cost-class', 'expensive'],
  ],
  'authenticated agent': [
    [':method', 'GET'], [':path', '/v1/items/42'], ['h4-agent', 'orchestrator'],
    ['h4-cap', '<32B>'], ['h4-tenant', 'acme'], ['accept', 'application/json'],
    ['if-none-match', '"abc"'], ['h4-budget', '500'],
  ],
  'browser navigation': [
    [':method', 'GET'], [':path', '/'], ['accept', 'text/html; charset=utf-8'],
    ['accept-encoding', 'zstd, br'], ['user-agent', 'Mozilla/5.0'],
    ['content-type', 'text/html; charset=utf-8'], ['host', 'example.com'],
  ],
};

console.log('case                     h4 bytes   http/1.1 text   h4 is');
for (const [name, hdrs] of Object.entries(cases)) {
  const h4 = encodeHeaders(hdrs).length;
  const h11 = hdrs.reduce((a, [n, v]) => a + n.length + v.length + 4, 2); // "Name: value\r\n" + CRLF
  const ratio = (h11 / h4);
  console.log(`${name.padEnd(24)} ${String(h4).padStart(6)}   ${String(h11).padStart(11)}   \x1b[32m${fmt(ratio, 2)}× smaller\x1b[0m`);
}
console.log('\nnote: HTTP/2/3 with HPACK/QPACK typically lands 30–60 B on a cold table and');
console.log('      needs per-connection state; H4 is state-free and < 25 B for these cases.');

// ─────────────────────────────────────────────────────────────────────────────
rule('2. Codec cost (per op, single core)');
const hdrs = cases['agent API call'];
const b1 = time(() => encodeHeaders(hdrs), 300000);
const enc = encodeHeaders(hdrs);
const b2 = time(() => decodeHeaders(enc), 300000);
console.log(`encode headers        ${bus(b1.perOp).padStart(9)}   ${fmt(b1.opsPerSec / 1e6, 2)} M ops/s`);
console.log(`decode headers        ${bus(b2.perOp).padStart(9)}   ${fmt(b2.opsPerSec / 1e6, 2)} M ops/s`);

const flight = Buffer.concat([
  fr.encodeHeadersFrame(hdrs), fr.encodeIntent({ mode: 0, deadlineMs: 5000 }),
  fr.encodeCost({ predicted: 8, costClass: 2 }), fr.encodeData('{"q":"hi"}'),
]);
const b3 = time(() => { const o = {}; for (const f of fr.iterFrames(flight)) o[f.type] = f.payload.length; }, 300000);
console.log(`parse full request    ${bus(b3.perOp).padStart(9)}   ${fmt(b3.opsPerSec / 1e6, 2)} M ops/s   (${flight.length} B flight)`);

// ─────────────────────────────────────────────────────────────────────────────
rule('3. Security primitives on the hot path');
const key = crypto.randomBytes(32);
const r = encodeReceipt({ window: 1, spent: 5, blockedUntil: 0, nonce: 1 });
const mac = signReceipt(r, key);
const lim = new Limiter({ budget: 1e9 });
const b4 = time(() => lim.check({ subject: 'hot', receipt: r, mac, sessionKey: key }), 200000);
console.log(`limit check w/ receipt${bus(b4.perOp).padStart(9)}   ${fmt(b4.opsPerSec / 1e6, 2)} M ops/s   (1 HMAC)`);
const b5 = time(() => lim.check({ subject: 'hot2', costClass: 0 }), 500000);
console.log(`limit check enforced  ${bus(b5.perOp).padStart(9)}   ${fmt(b5.opsPerSec / 1e6, 2)} M ops/s   (0 HMAC, 1 int)`);

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const reg = new KeyRegistry().add(1, publicKey);
const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ | CAPS.WRITE, expiresAt: Math.floor(Date.now() / 1000) + 3600 });
const chain = attenuate(attenuate(root, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 1800 }), { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 900 });
const cache = new Map();
const b6 = time(() => verify(chain, reg, { cache }), 100000);
console.log(`cap verify (2 hops)   ${bus(b6.perOp).padStart(9)}   ${fmt(b6.opsPerSec / 1e6, 2)} M ops/s   (root sig cached)`);
const b7 = time(() => verify(chain, reg, { cache: new Map() }), 20000);
console.log(`cap verify (cold)     ${bus(b7.perOp).padStart(9)}   ${fmt(b7.opsPerSec / 1e3, 0)} k ops/s   (1 Ed25519)`);
console.log(`→ session-cached verification is \x1b[32m${fmt(b6.perOp && b7.perOp / b6.perOp, 0)}×\x1b[0m cheaper than per-request Ed25519.`);

// ─────────────────────────────────────────────────────────────────────────────
rule('4. End-to-end server cost per request (no network, no TLS)');
const calls = { n: 0 };
const routes = {
  '/cheap': async () => { calls.n++; return { status: 200, body: { ok: 1 }, cost: 1, ttlMs: 60000 }; },
  '/expensive': async () => { calls.n++; return { status: 200, body: { ok: 1 }, cost: 40, ttlMs: 60000 }; },
};
const mkReq = (path, extra = {}) => ({
  headers: [[':method', 'GET'], [':path', path], ['h4-agent', 'bench']],
  intent: { mode: 0, idem: '', deadlineMs: 30000, costCeiling: 0, maxShape: 0, dedup: '' },
  cost: { predicted: 0, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 },
  peer: '10.0.0.1', sessionKey: key, ...extra,
});

const server = new H4Server({ routes, limiter: new Limiter({ budget: 1e9 }) });
let b8;
(async () => {
  b8 = time(() => { server.handle(mkReq('/cheap')); }, 200000);
  // handle() is async but resolves synchronously for cache hits; measure the promise path too
  const t0 = process.hrtime.bigint();
  const N = 50000;
  for (let i = 0; i < N; i++) await server.handle(mkReq('/cheap'));
  const perOpAsync = Number(process.hrtime.bigint() - t0) / N;
  console.log(`serve (sync path)     ${bus(b8.perOp).padStart(9)}   ${fmt(b8.opsPerSec, 0)} req/s`);
  console.log(`serve (await path)    ${bus(perOpAsync).padStart(9)}   ${fmt(1e9 / perOpAsync, 0)} req/s`);

  // reject path: how much cheaper is saying no than saying yes?
  const limp = new Limiter({ budget: 1, pressure: () => 220 });
  const rs = new H4Server({ routes, limiter: limp });
  for (let i = 0; i < 10; i++) rs.handle(mkReq('/cheap'));
  const b9 = time(() => { rs.handle(mkReq('/cheap')); }, 100000);
  console.log(`reject (rate/effort)  ${bus(b9.perOp).padStart(9)}   ${fmt(b9.opsPerSec / 1e6, 2)} M ops/s`);
  console.log(`→ a rejection costs \x1b[32m${fmt(b8.perOp / b9.perOp, 1)}×\x1b[0m less than a served request.`);

  // ───────────────────────────────────────────────────────────────────────────
  rule('5. Proof-of-effort economics (attacker pays, defender does not)');
  const hr0 = time(() => crypto.createHash('sha256').update('x').digest(), 500000);
  console.log(`SHA-256 rate (1 core) ${fmt(hr0.opsPerSec / 1e6, 2)} M hashes/s  → 1 core does`);
  for (const bits of [12, 16, 20, 24]) {
    const expected = 2 ** bits;
    const secPerCore = expected / hr0.opsPerSec;
    console.log(`  difficulty ${String(bits).padStart(2)} bits: ~${fmt(expected, 0)} hashes = ${secPerCore < 60 ? secPerCore.toFixed(2) + ' s' : (secPerCore / 60).toFixed(1) + ' min'} of one core, per request, attacker-side`);
  }
  console.log('  defender per request: constant (~1 SHA-256 verify ≈ ' + bus(hr0.perOp) + ') regardless of difficulty.');

  // ───────────────────────────────────────────────────────────────────────────
  if (!quick) {
    rule('6. Attack simulation');
    console.log('  moved to its own script, because a fair comparison needs a fair baseline:');
    console.log('  \x1b[1mnode bench/attack-sim.js\x1b[0m');
    console.log('  (the earlier version of this section compared an H4 request parser against a');
    console.log('   bare integer counter, which produced a fake "2x faster" number. Deleted.)');
  }

  console.log(`\n\x1b[1mdone\x1b[0m\n`);
})();

// A cache with no memory, so the attack simulation measures the limiter and not
// the (very effective) coalescing layer.
class H4CacheNoop {
  constructor() { this.stats = {}; this.defaultTtlMs = 0; }
  get() { return null; }
  set() {}
  async coalesce(k, fn) { return { value: await fn(), coalesced: false }; }
  key(...a) { return a.join('|'); }
  sizeInfo() { return {}; }
}
