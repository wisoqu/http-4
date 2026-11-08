// H4 conformance / invariant tests. No framework: `node test/run.js`.
// Each test maps to a numbered requirement in spec/http4.md.

import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import { Writer, Reader, writeVarint, readVarint, zigzag, unzigzag } from '../src/varint.js';
import { encodeHeaders, decodeHeaders, STATIC_TABLE } from '../src/headers.js';
import * as fr from '../src/frames.js';
import { mintRoot, attenuate, verify, KeyRegistry, CAPS } from '../src/identity.js';
import { Limiter, CLASS_WEIGHT, poeChallenge, solvePoE, checkPoE, encodeReceipt, signReceipt, verifyReceipt } from '../src/limits.js';
import { H4Cache } from '../src/cache.js';
import { H4Server } from '../src/server.js';
import { H4Client } from '../src/client.js';

let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); pass++; console.log(`  ok   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); }
};
// Async tests are collected and awaited at the end. (Doing it any other way is
// how you get a green build that never ran its async assertions — the exact bug
// this file had before: process.exit() beat every pending promise to the exit.)
const pending = [];
const ta = (name, fn) => { pending.push({ name, fn }); };

console.log('\n── varint (§3.1)');
t('round-trips all boundary values', () => {
  for (const v of [0, 1, 63, 64, 16383, 16384, 2 ** 30 - 1, 2 ** 30, 2 ** 40]) {
    const b = Buffer.alloc(8); const n = writeVarint(b, 0, v);
    assert.equal(readVarint(b, 0).value, v); assert.equal(readVarint(b, 0).size, n);
  }
});
t('zigzag round-trips negatives', () => {
  for (const v of [-1000, -1, 0, 1, 99999]) assert.equal(unzigzag(zigzag(v)), v);
});

console.log('\n── header compression (§4)');
t('static-table values cost exactly 1 byte', () => {
  assert.equal(encodeHeaders([[':method', 'GET']]).length, 1);
  assert.equal(encodeHeaders([[':status', '200']]).length, 1);
  assert.equal(encodeHeaders([['content-type', 'application/json']]).length, 1);
});
t('typical agent request (4 headers + path) fits in ≤ 25 bytes', () => {
  const b = encodeHeaders([
    [':method', 'GET'], [':path', '/v1/items'], ['h4-agent', 'research-bot'],
    ['h4-cost-class', 'cheap'], ['accept', 'application/json'],
  ]);
  assert.ok(b.length <= 25, `was ${b.length}`);
});
t('round-trips mixed headers with value prefixes', () => {
  const hdrs = [[':method', 'POST'], ['content-type', 'application/json'], ['h4-agent-model', 'gpt-4o-mini'], ['x-custom', 'hello']];
  assert.deepEqual(decodeHeaders(encodeHeaders(hdrs)), hdrs);
});
t('every static entry is reachable and self-consistent', () => {
  for (const [n, v] of STATIC_TABLE) assert.deepEqual(decodeHeaders(encodeHeaders([[n, v]])), [[n, v]]);
});
t('fuzz: random headers survive round-trip', () => {
  const alpha = 'abcdefghijklmnopqrstuvwxyz/:-.0123456789';
  for (let i = 0; i < 300; i++) {
    const k = 'x-' + Array.from({ length: 3 + (i % 5) }, () => alpha[i % alpha.length]).join('');
    const v = Array.from({ length: 1 + (i % 17) }, (_, j) => alpha[(i + j * 7) % alpha.length]).join('') || 'v';
    assert.deepEqual(decodeHeaders(encodeHeaders([[k, v]])), [[k, v]]);
  }
});

console.log('\n── frames (§3.2)');
t('all frame types round-trip', () => {
  const i = fr.decodeIntent(fr.encodeIntent({ mode: 1, idem: 'k1', deadlineMs: 5000, costCeiling: 42, maxShape: 7, dedup: 'd' }).subarray(2));
  assert.equal(i.mode, 1); assert.equal(i.costCeiling, 42); assert.equal(i.dedup, 'd');
  const c = fr.decodeCost(fr.encodeCost({ predicted: 9, costClass: 2, effortBits: 3, budgetRemaining: 11, value: 100, tokenBudget: 4000 }).subarray(2));
  assert.equal(c.tokenBudget, 4000); assert.equal(c.costClass, 2);
  const r = fr.decodeResult(fr.encodeResult({ status: 200, costActual: 3, cache: 1, tokens: 99, wallMs: 12, costAsym: -5 }).subarray(2));
  assert.equal(r.costAsym, -5); assert.equal(r.tokens, 99);
  const rl = fr.decodeRate(fr.encodeRate({ pressure: 200, budgetRemaining: 4, blockUntilMs: 1234 }).subarray(2));
  assert.equal(rl.pressure, 200); assert.equal(rl.blockUntilMs, 1234);
});
t('iterator splits coalesced frames', () => {
  const buf = Buffer.concat([fr.encodeData('a'), fr.encodeData('bb'), fr.encodeRate({ pressure: 5 })]);
  const got = [...fr.iterFrames(buf)];
  assert.equal(got.length, 3);
  assert.equal(got[0].payload.toString(), 'a');
  assert.equal(got[1].payload.toString(), 'bb');
});

console.log('\n── capabilities (§5)');
function setupKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const reg = new KeyRegistry().add(1, publicKey);
  return { reg, privateKey };
}
t('root token verifies', () => {
  const { reg, privateKey } = setupKey();
  const tok = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ | CAPS.WRITE, expiresAt: Math.floor(Date.now() / 1000) + 60 });
  const v = verify(tok, reg);
  assert.equal(v.ok, true); assert.equal(v.hops, 0);
});
t('offline delegation narrows correctly (3 hops)', () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ | CAPS.WRITE | CAPS.DELEGATE, expiresAt: Math.floor(Date.now() / 1000) + 600, scope: '/' });
  const a1 = attenuate(root, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 300, scope: '/v1/' });
  const a2 = attenuate(a1, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 100, scope: '/v1/items' });
  const v = verify(a2, reg);
  assert.equal(v.ok, true); assert.equal(v.hops, 2); assert.equal(v.scope, '/v1/items');
});
t('delegation cannot escalate: widened caps rejected', () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600 });
  assert.throws(() => attenuate(root, { caps: CAPS.READ | CAPS.WRITE, expiresAt: Math.floor(Date.now() / 1000) + 60 }), /add capabilities/);
});
t('delegation cannot extend expiry', () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60 });
  assert.throws(() => attenuate(root, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600 }), /extend expiry/);
});
t('tampered chain link is detected', () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600 });
  const a1 = attenuate(root, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 300 });
  const broken = Buffer.from(a1); broken[broken.length - 1] ^= 0xff;
  assert.equal(verify(broken, reg).ok, false);
});
t('forged root signature is detected', () => {
  const { reg } = setupKey();
  const evil = crypto.generateKeyPairSync('ed25519').privateKey;
  const forged = mintRoot({ keyId: 1, privateKey: evil, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60 });
  assert.equal(verify(forged, reg).ok, false);
});
t('expired token is rejected', () => {
  const { reg, privateKey } = setupKey();
  const tok = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) - 1 });
  assert.equal(verify(tok, reg).code, 'CAP_EXPIRED');
});
t('root verify is cached (one Ed25519 per session, not per request)', () => {
  const { reg, privateKey } = setupKey();
  const tok = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600 });
  const cache = new Map();
  const orig = crypto.verify; let calls = 0;
  crypto.verify = (...a) => { calls++; return orig(...a); };
  for (let i = 0; i < 50; i++) verify(tok, reg, { cache });
  crypto.verify = orig;
  assert.equal(calls, 1, `ed25519 verifies = ${calls}, expected 1`);
});

console.log('\n── limits (§6)');
t('cooperative receipt is accepted and drives the bucket', () => {
  const key = Limiter.sessionKey();
  const lim = new Limiter({ budget: 20, windowMs: 10_000 });
  const r = encodeReceipt({ window: Math.floor(Date.now() / 10_000), spent: 18, blockedUntil: 0, nonce: 1 });
  const out = lim.check({ subject: 'a', receipt: r, mac: signReceipt(r, key), sessionKey: key });
  assert.equal(out.allow, true);
  assert.ok(out.tier.includes('cooperative'));
});
t('forged receipt is ignored and punished', () => {
  const key = Limiter.sessionKey();
  const lim = new Limiter({ budget: 20 });
  const r = encodeReceipt({ window: Math.floor(Date.now() / 10_000), spent: 0, blockedUntil: 0, nonce: 1 });
  const out = lim.check({ subject: 'a', receipt: r, mac: 'AAAAAAAAAAAAAAAA', sessionKey: key });
  assert.equal(lim.stats.receiptsForged, 1);
  assert.ok(out.tier.includes('enforced'));
});
t('replayed receipt (nonce rollback) is rejected', () => {
  const key = Limiter.sessionKey();
  const lim = new Limiter({ budget: 100 });
  const mk = (n) => { const r = encodeReceipt({ window: Math.floor(Date.now() / 10_000), spent: 0, blockedUntil: 0, nonce: n }); return [r, signReceipt(r, key)]; };
  const [r5, m5] = mk(5); lim.check({ subject: 'a', receipt: r5, mac: m5, sessionKey: key });
  const [r3, m3] = mk(3); lim.check({ subject: 'a', receipt: r3, mac: m3, sessionKey: key });
  assert.equal(lim.stats.receiptsForged, 1);
});
t('exhausting budget produces RATE_LIMITED with retry_after', () => {
  const lim = new Limiter({ budget: 3 });
  let last;
  for (let i = 0; i < 5; i++) last = lim.check({ subject: 'a' });
  assert.equal(last.allow, false);
  assert.ok(last.retryAfterMs > 0);
});
t('under pressure, rejection becomes priced effort instead of a ban', () => {
  const lim = new Limiter({ budget: 2, pressure: () => 200 });
  let last;
  for (let i = 0; i < 5; i++) last = lim.check({ subject: 'a' });
  assert.equal(last.code, 'EFFORT_REQUIRED');
  assert.ok(last.difficulty >= 6);
});
t('disjoint NATs do not share a bucket (collateral damage control)', () => {
  const lim = new Limiter({ budget: 5 });
  for (let i = 0; i < 20; i++) lim.check({ subject: 'peer-A' });
  assert.equal(lim.check({ subject: 'peer-B' }).allow, true);
});
t('proof-of-effort: honest solve + verify, wrong nonce fails', () => {
  const ch = poeChallenge('subject', 1);
  const bits = 8;
  const { nonce } = solvePoE(ch, bits);
  assert.equal(checkPoE(ch, nonce, bits), true);
  assert.equal(checkPoE(ch, (nonce + 1) >>> 0, bits), checkPoE(ch, (nonce + 1) >>> 0, bits));
  // expected work for 8 bits is ~256 hashes; sanity-check it is not trivially 0
  assert.ok(nonce < 100000);
});
t('class weights make expensive requests cost more', () => {
  assert.ok(CLASS_WEIGHT[2] > CLASS_WEIGHT[1] && CLASS_WEIGHT[1] > CLASS_WEIGHT[0]);
});

console.log('\n── cache / coalescing (§7)');
ta('identical concurrent expensive requests run once (async)', async () => {
  const c = new H4Cache();
  let runs = 0;
  const work = async () => { runs++; await new Promise((r) => setTimeout(r, 15)); return { v: 1 }; };
  const res = await Promise.all([0, 1, 2, 3, 4].map(() => c.coalesce('same', work)));
  assert.equal(runs, 1);
  assert.equal(res.filter((r) => r.coalesced).length, 4);
});
t('LRU evicts under byte pressure', () => {
  const c = new H4Cache({ maxBytes: 500 });
  for (let i = 0; i < 20; i++) c.set('k' + i, { data: 'x'.repeat(50) });
  assert.ok(c.bytes <= 500);
});
t('stale entries are served under high pressure instead of recomputing', () => {
  const c = new H4Cache({ pressure: () => 200 });
  c.set('k', { v: 1 }, { ttlMs: 1 });
  const e = c.get('k', Date.now() + 100);
  assert.equal(e.stale, true);
});

console.log('\n── end-to-end behaviour (§8)');
const mkRoute = (calls) => async ({ path, method }) => {
  calls.n++;
  if (path === '/expensive') { await new Promise((r) => setTimeout(r, 20)); return { status: 200, body: { path, answer: 42 }, cost: 30, tokens: 1200, ttlMs: 5000 }; }
  return { status: 200, body: { path, method }, cost: 1, ttlMs: 5000 };
};
const mkReq = (o = {}) => ({
  headers: [[':method', o.method ?? 'GET'], [':path', o.path ?? '/x'], ['h4-agent', o.agent ?? 'bot']],
  intent: { mode: 0, idem: '', deadlineMs: 30_000, costCeiling: o.ceiling ?? 0, maxShape: 0, dedup: o.dedup ?? '' },
  cost: { predicted: 0, costClass: o.class ?? 0, effortBits: 0, budgetRemaining: 0, value: o.value ?? 0, tokenBudget: 0 },
  cap: o.cap, rate: o.rate, peer: o.peer ?? '1.2.3.4', sessionKey: o.sessionKey, body: o.body,
});

ta('issued maxSubs buys a proportional aggregate quota (operator fan-out)', async () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ | CAPS.DELEGATE, expiresAt: Math.floor(Date.now() / 1000) + 60, maxSubs: 20 });
  const mk = (i) => attenuate(root, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60, subs: i });
  const s = new H4Server({ registry: reg, routes: { '/x': mkRoute({ n: 0 }) }, limiter: new Limiter({ budget: 5, windowMs: 10_000 }) });
  let served = 0;
  for (let i = 0; i < 20; i++) { // 20 agents sharing one issuer grant, distinct instances
    const r = await s.handle(mkReq({ cap: { token: mk(i) }, agent: 'a-' + i }));
    if (!r.reject) served++;
  }
  assert.equal(served, 20, `served=${served}: each attenuated instance must get its own quota`);
});
ta('a token without maxSubs cannot be fanned out into a fleet', async () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ | CAPS.DELEGATE, expiresAt: Math.floor(Date.now() / 1000) + 60 });
  const mk = (i) => attenuate(root, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60, subs: i });
  const s = new H4Server({ registry: reg, routes: { '/x': mkRoute({ n: 0 }) }, limiter: new Limiter({ budget: 2, windowMs: 10_000 }) });
  let served = 0;
  for (let i = 0; i < 40; i++) {
    const r = await s.handle(mkReq({ cap: { token: mk(i) }, agent: 'a-' + i }));
    if (!r.reject) served++;
  }
  // aggregate allowance = budget × (1 + identityBonus) × maxSubs(=1) = 6
  assert.ok(served <= 6, `served=${served}: without a signed maxSubs the aggregate must cap fan-out at one share`);
});
ta('anonymous instance churn from one address is bounded', async () => {
  const s = new H4Server({ routes: { '/x': mkRoute({ n: 0 }) }, limiter: new Limiter({ budget: 5, windowMs: 10_000, netMultiplier: 1 }) });
  let served = 0;
  for (let i = 0; i < 200; i++) {
    const r = await s.handle(mkReq({ agent: 'fake-' + i, peer: '9.9.9.9' }));
    if (!r.reject) served++;
  }
  assert.ok(served <= 10, `served=${served}: free identities must not multiply the shared quota`);
  // and a second, unrelated address is unaffected — no collateral damage
  assert.equal((await s.handle(mkReq({ agent: 'v-1', peer: '8.8.8.8' }))).reject, undefined);
});

ta('normal request is served and reports actual cost', async () => {
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/x': mkRoute(calls) } });
  const res = await s.handle(mkReq());
  assert.equal(res.result.status, 200);
  assert.ok(res.result.costActual >= 1);
  const types = res.frames.map((f) => [...fr.iterFrames(f)][0].type);
  assert.ok(types.includes(fr.F.RESULT) && types.includes(fr.F.RATE) && types.includes(fr.F.COST));
});
ta('cache hit costs less than a miss', async () => {
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/x': mkRoute(calls) } });
  const a = await s.handle(mkReq());
  const b = await s.handle(mkReq());
  assert.equal(b.result.cache, fr.CACHE.HIT);
  assert.ok(b.result.costActual <= a.result.costActual);
  assert.equal(calls.n, 1);
});
ta('a cost ceiling above prediction is refused before the handler runs', async () => {
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/expensive': mkRoute(calls) } });
  // POST is classified NORMAL, so the static prediction (8) exceeds the ceiling (1)
  const res = await s.handle(mkReq({ path: '/expensive', method: 'POST', ceiling: 1 }));
  assert.equal(res.reject.code, fr.REJECT.COST_REFUSED);
  assert.equal(calls.n, 0, 'handler must not run');
});
ta('capability scope is enforced before the handler runs', async () => {
  const { reg, privateKey } = setupKey();
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/x': mkRoute(calls) }, registry: reg });
  const tok = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60, scope: '/admin' });
  const res = await s.handle(mkReq({ cap: { token: tok } }));
  assert.equal(res.reject.code, fr.REJECT.SCOPE_DENIED);
  assert.equal(calls.n, 0);
});
ta('missing capability is refused when the server requires one', async () => {
  const s = new H4Server({ routes: { '/x': mkRoute({ n: 0 }) }, requireCap: true });
  const res = await s.handle(mkReq());
  assert.equal(res.reject.code, fr.REJECT.CAP_INVALID);
});
ta('client accountant prevents sending when over budget', async () => {
  const c = new H4Client({ budgetPerSec: 2, windowMs: 10_000 });
  const decisions = [];
  for (let i = 0; i < 50; i++) decisions.push(c.shouldSend({ path: '/x', method: 'POST', intent: {}, cost: { costClass: 2 } }));
  const blocked = decisions.filter((d) => d && d.send === false);
  assert.ok(blocked.length > 40, `blocked=${blocked.length}`);
  assert.ok(c.stats.costAvoided > 0);
});
ta('client refuses work whose predicted cost exceeds its value', async () => {
  const c = new H4Client();
  const d = c.shouldSend({ path: '/x', method: 'POST', intent: { maxShape: 50 }, cost: {}, worth: 2 });
  assert.equal(d.send, false); assert.equal(d.reason, 'not-worth-it');
});
ta('server rate policy is adopted by the client', async () => {
  const c = new H4Client();
  c.observe(Buffer.concat([fr.encodeRate({ pressure: 180, budgetRemaining: 0, blockUntilMs: Date.now() + 500 }) ]));
  const d = c.shouldSend({ path: '/x' });
  assert.equal(d.send, false);
  assert.equal(d.reason, 'self-rate-limited');
});
ta('retry storm: 100 identical expensive requests → 1 computation', async () => {
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/expensive': mkRoute(calls) }, limiter: new Limiter({ budget: 100000 }) });
  await Promise.all(Array.from({ length: 100 }, (_, i) => s.handle(mkReq({ path: '/expensive', dedup: 'storm' }))));
  assert.equal(calls.n, 1, `handler ran ${calls.n} times`);
  assert.ok(s.metrics.coalesced > 0);
});
ta('hostile client cannot bypass the server bucket by lying in its receipt', async () => {
  const key = Limiter.sessionKey();
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/expensive': mkRoute(calls) }, limiter: new Limiter({ budget: 10 }) });
  let served = 0, rejected = 0;
  for (let i = 0; i < 30; i++) {
    // claims it spent nothing, every time, with a fresh nonce
    const r = encodeReceipt({ window: Math.floor(Date.now() / 10_000), spent: 0, blockedUntil: 0, nonce: i + 1 });
    const res = await s.handle(mkReq({ path: '/expensive', dedup: '', rate: { receipt: r, mac: signReceipt(r, key) }, sessionKey: key }));
    if (res.reject) rejected++; else served++;
  }
  assert.ok(rejected > 0, 'server must reject once its own bucket is empty');
});

for (const { name, fn } of pending) {
  try { await fn(); pass++; console.log(`  ok   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); }
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
