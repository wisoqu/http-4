// H4 conformance / invariant tests. No framework: `node test/run.js`.
// Each test maps to a numbered requirement in spec/http4.md.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import http2 from 'node:http2';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';

import * as h4Index from '../src/index.js';
import { Writer, Reader, writeVarint, readVarint, readVarintBig, zigzag, unzigzag } from '../src/varint.js';
import { encodeHeaders, decodeHeaders, STATIC_TABLE } from '../src/headers.js';
import * as fr from '../src/frames.js';
import { mintRoot, attenuate, verify, KeyRegistry, CAPS, isSubScope } from '../src/identity.js';
import {
  Limiter, CLASS_WEIGHT, poeChallenge, solvePoE, checkPoE,
  encodeReceipt, decodeReceipt, signReceipt, verifyReceipt,
} from '../src/limits.js';
import { H4Cache, hashKey } from '../src/cache.js';
import { H4Server } from '../src/server.js';
import { H4Client } from '../src/client.js';
import { createServer, connect, packMessage } from '../src/wire.js';
import { createGateway, createH2Gateway } from '../src/gateway.js';

let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); pass++; console.log(`  ok   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); }
};
const pending = [];
const ta = (name, fn) => { pending.push({ name, fn }); };

console.log('\n── package entrypoint (§0)');
t('index.js exports CAPS and public surface without star-export collision', () => {
  assert.equal(h4Index.CAPS.READ, 1);
  assert.equal(typeof h4Index.H4Server, 'function');
  assert.equal(typeof h4Index.H4Client, 'function');
  assert.equal(typeof h4Index.createGateway, 'function');
});

console.log('\n── varint (§3.1)');
t('round-trips all boundary values', () => {
  for (const v of [0, 1, 63, 64, 16383, 16384, 2 ** 30 - 1, 2 ** 30, 2 ** 40]) {
    const b = Buffer.alloc(8); const n = writeVarint(b, 0, v);
    assert.equal(readVarint(b, 0).value, v); assert.equal(readVarint(b, 0).size, n);
  }
});
t('supports full 62-bit QUIC varints via BigInt', () => {
  const maxQuic = 0x3fffffffffffffffn;
  const b = Buffer.alloc(8);
  assert.equal(writeVarint(b, 0, maxQuic), 8);
  assert.equal(readVarintBig(b, 0).value, maxQuic);
});
t('rejects negative, non-integer, and truncated varints (§3.1 UB guard)', () => {
  const b = Buffer.alloc(8);
  assert.throws(() => writeVarint(b, 0, -1), RangeError);
  assert.throws(() => writeVarint(b, 0, 1.5), RangeError);
  assert.throws(() => writeVarint(b, 0, NaN), RangeError);
  assert.throws(() => readVarint(Buffer.alloc(0), 0), RangeError);
  assert.throws(() => readVarint(Buffer.from([0x40]), 0), RangeError);
  assert.throws(() => readVarint(Buffer.from([0x80, 0x01]), 0), RangeError);
  assert.throws(() => readVarint(Buffer.from([0xc0, 0x01, 0x02]), 0), RangeError);
  assert.throws(() => new Reader(Buffer.from([5, 65, 66])).bytes(), RangeError);
});
t('zigzag round-trips negatives and large >30-bit values without sign overflow', () => {
  for (const v of [-1_500_000_000, -(2 ** 30), -1000, -1, 0, 1, 99999, 2 ** 30, 1_500_000_000, 2 ** 40]) {
    const z = zigzag(v);
    assert.ok(z >= 0, `zigzag(${v}) must be non-negative, got ${z}`);
    assert.equal(unzigzag(z), v);
  }
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
t('static-table names at index ≥ 31 round-trip losslessly (host, user-agent, h4-rl, etag)', () => {
  const hdrs = [
    ['host', 'example.com'],
    ['user-agent', 'Mozilla/5.0'],
    ['h4-rl', '1.abc.5.0.1,mac123'],
    ['if-none-match', '"etag-42"'],
    ['content-type', 'text/plain'],
    ['cache-control', 'max-age=300'],
  ];
  assert.deepEqual(decodeHeaders(encodeHeaders(hdrs)), hdrs);
});
t('normalizes mixed-case header names to lowercase', () => {
  const got = decodeHeaders(encodeHeaders([['Content-Type', 'text/plain'], ['x-Custom-Key', 'https://api.acme.io']]));
  assert.deepEqual(got, [['content-type', 'text/plain'], ['x-custom-key', 'https://api.acme.io']]);
});
t('rejects out-of-bounds static indices and reserved header tags', () => {
  assert.throws(() => decodeHeaders(Buffer.from([0x80 | 120])), RangeError);
  assert.throws(() => decodeHeaders(Buffer.from([0x60 | 1, 99, 1, 65])), RangeError);
  assert.throws(() => decodeHeaders(Buffer.from([0x15])), RangeError);
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
t('all frame types round-trip (including HELLO, ACCESS, CANCEL, PING, GOAWAY)', () => {
  const i = fr.decodeIntent(fr.encodeIntent({ mode: 1, idem: 'k1', deadlineMs: 5000, costCeiling: 42, maxShape: 7, dedup: 'd' }).subarray(2));
  assert.equal(i.mode, 1); assert.equal(i.costCeiling, 42); assert.equal(i.dedup, 'd');
  const c = fr.decodeCost(fr.encodeCost({ predicted: 9, costClass: 2, effortBits: 3, budgetRemaining: 11, value: 100, tokenBudget: 4000 }).subarray(2));
  assert.equal(c.tokenBudget, 4000); assert.equal(c.costClass, 2);
  const r = fr.decodeResult(fr.encodeResult({ status: 200, costActual: 3, cache: 1, tokens: 99, wallMs: 12, costAsym: -5 }).subarray(2));
  assert.equal(r.costAsym, -5); assert.equal(r.tokens, 99);
  const rl = fr.decodeRate(fr.encodeRate({ pressure: 200, budgetRemaining: 4, blockUntilMs: 1234 }).subarray(2));
  assert.equal(rl.pressure, 200); assert.equal(rl.blockUntilMs, 1234);

  const hFrame = [...fr.iterFrames(fr.encodeHello({ proto: 'h4/1', tableVersion: 1, budget: 200, windowMs: 10_000, sessionKey: Buffer.alloc(32, 7), serverId: 'edge-1', agent: 'bot/1' }))][0];
  const h = fr.decodeHello(hFrame.payload);
  assert.equal(h.proto, 'h4/1'); assert.equal(h.ratePolicy.budget, 200); assert.equal(h.sessionKey.length, 32);

  const aFrame = [...fr.iterFrames(fr.encodeAccess({ tier: 'cooperative', cache: 1, costActual: 2, predicted: 3, wallUs: 45 }))][0];
  assert.equal(fr.decodeAccess(aFrame.payload).tier, 'cooperative');
  assert.equal(fr.decodePing([...fr.iterFrames(fr.encodePing({ id: 77 }))][0].payload).id, 77);
  assert.equal(fr.decodeCancel([...fr.iterFrames(fr.encodeCancel({ code: 3 }))][0].payload).code, 3);
  assert.equal(fr.decodeGoaway([...fr.iterFrames(fr.encodeGoaway({ lastStream: 12, reason: 1 }))][0].payload).lastStream, 12);
});
t('iterator splits coalesced frames and rejects truncated payloads', () => {
  const buf = Buffer.concat([fr.encodeData('a'), fr.encodeData('bb'), fr.encodeRate({ pressure: 5 })]);
  const got = [...fr.iterFrames(buf)];
  assert.equal(got.length, 3);
  assert.equal(got[0].payload.toString(), 'a');
  assert.equal(got[1].payload.toString(), 'bb');
  assert.throws(() => [...fr.iterFrames(buf.subarray(0, buf.length - 2))], RangeError);
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
t('tampering with signed maxSubs header is rejected (§5.4)', () => {
  const { reg, privateKey } = setupKey();
  const tok = Buffer.from(mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600, maxSubs: 1 }));
  // byte 0 = ver(1), byte 1 = keyId(1), byte 2 = maxSubs(1) → flip maxSubs to 50
  tok[2] = 50;
  const v = verify(tok, reg);
  assert.equal(v.ok, false);
  assert.equal(v.code, 'CAP_INVALID');
});
t('verifyCache binds claims0 + sig0 so cached sig0 cannot validate forged claims (§5.3)', () => {
  const { reg, privateKey } = setupKey();
  const cache = new Map();
  const valid = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600, scope: '/public', tenant: 'bob' });
  assert.equal(verify(valid, reg, { cache }).ok, true);

  // Build an attacker token with admin claims, then transplant `valid`'s 64-byte sig0
  const fakeKey = crypto.generateKeyPairSync('ed25519').privateKey;
  const forged = Buffer.from(mintRoot({ keyId: 1, privateKey: fakeKey, caps: CAPS.READ | CAPS.WRITE, expiresAt: Math.floor(Date.now() / 1000) + 600, scope: '/', tenant: 'admin' }));
  valid.subarray(valid.length - 64).copy(forged, forged.length - 64);
  const res = verify(forged, reg, { cache });
  assert.equal(res.ok, false);
  assert.equal(res.code, 'CAP_INVALID');
});
t('non-delegable leaf tokens reject HMAC chain extension (§5.2)', () => {
  const { reg, privateKey } = setupKey();
  const nonDelegable = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600, delegable: 0 });
  assert.throws(() => attenuate(nonDelegable, { caps: CAPS.READ }), /not delegable/);

  // Even if an attacker manually appends a valid HMAC128 link over sig0, verify() rejects it
  const sig0 = nonDelegable.subarray(nonDelegable.length - 64);
  const w = new Writer(64);
  w.varint(CAPS.READ).varint(Math.floor(Date.now() / 1000) + 300).bytes(Buffer.from('/')).u8(0).bytes(Buffer.from('')).varint(1);
  const claims1 = w.finish();
  const link1 = crypto.createHmac('sha256', sig0).update(claims1).digest().subarray(0, 16);
  const manual = new Writer(256).raw(nonDelegable).bytes(claims1).raw(link1).finish();
  assert.equal(verify(manual, reg).code, 'SCOPE_DENIED');
});
t('tenant claim cannot be switched during attenuation (§5.2)', () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600, tenant: 'acme' });
  assert.throws(() => attenuate(root, { tenant: 'globex' }), /change tenant/);
});
t('scope check prevents prefix-sibling confusion and path traversal (§5.2)', () => {
  assert.equal(isSubScope('/v1/items', '/v1/items'), true);
  assert.equal(isSubScope('/v1/items', '/v1/items/42'), true);
  assert.equal(isSubScope('/v1/items', '/v1/items-secret'), false);
  assert.equal(isSubScope('/v1/items', '/v1/items/../admin'), false);
  assert.equal(isSubScope('/v1/items', '/v1/items/%2e%2e/admin'), false);
});
t('truncated tokens return MALFORMED without throwing', () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 600 });
  const a1 = attenuate(root, { caps: CAPS.READ });
  for (let cut = 0; cut < a1.length; cut += 7) {
    const res = verify(a1.subarray(0, cut), reg);
    assert.equal(res.ok, false);
  }
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
t('53-bit millisecond blockedUntil timestamps survive receipt round-trip (§6.2)', () => {
  const futureMs = Date.now() + 45_000;
  const rStr = encodeReceipt({ window: 123456, spent: 12, blockedUntil: futureMs, nonce: 9 });
  const parsed = decodeReceipt(rStr);
  assert.equal(parsed.blockedUntil, futureMs);
  assert.equal(parsed.nonce, 9);
});
t('forged receipt is ignored and punished', () => {
  const key = Limiter.sessionKey();
  const lim = new Limiter({ budget: 20 });
  const r = encodeReceipt({ window: Math.floor(Date.now() / 10_000), spent: 0, blockedUntil: 0, nonce: 1 });
  const out = lim.check({ subject: 'a', receipt: r, mac: 'AAAAAAAAAAAAAAAA', sessionKey: key });
  assert.equal(lim.stats.receiptsForged, 1);
  assert.ok(out.tier.includes('enforced'));
});
t('replayed receipt (nonce rollback) is rejected even across window rollover', () => {
  const key = Limiter.sessionKey();
  const lim = new Limiter({ budget: 100, windowMs: 10_000 });
  const t0 = 1_000_000;
  const mk = (win, n, spent = 0) => {
    const r = encodeReceipt({ window: win, spent, blockedUntil: 0, nonce: n });
    return [r, signReceipt(r, key)];
  };
  const [r5, m5] = mk(100, 5, 80);
  lim.check({ subject: 'a', receipt: r5, mac: m5, sessionKey: key }, t0);
  // Next window (t0 + 10_000): replaying nonce 5 or 3 is rejected, and stale window's spent=80 does not pollute new window
  const [r3, m3] = mk(100, 3, 80);
  lim.check({ subject: 'a', receipt: r3, mac: m3, sessionKey: key }, t0 + 10_000);
  assert.equal(lim.stats.receiptsForged, 1);
  const [r6, m6] = mk(100, 6, 95); // stale window=100 arriving in window=101
  const out = lim.check({ subject: 'a', receipt: r6, mac: m6, sessionKey: key }, t0 + 10_000);
  assert.equal(out.allow, true);
  assert.ok(out.budgetRemaining >= 95, `stale window spend leaked: remaining=${out.budgetRemaining}`);
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
t('proof-of-effort: honest solve + verify, single-use nonce blocks replay (§6.4)', () => {
  const lim = new Limiter({ budget: 1, pressure: () => 200 });
  const now = 60_000;
  const win = Math.floor(now / 30_000);
  const ch = poeChallenge('subj-1', win);
  const bits = 8;
  const { nonce } = solvePoE(ch, bits);
  assert.equal(checkPoE(ch, nonce, bits), true);
  assert.ok(lim.redeemPoE({ subject: 'subj-1', poeWindow: win, challenge: ch, nonce, difficulty: bits }, now));
  // Replaying the exact same PoE nonce a second time MUST fail
  assert.equal(lim.redeemPoE({ subject: 'subj-1', poeWindow: win, challenge: ch, nonce, difficulty: bits }, now), null);
});
t('stateless cluster session keys verify across independent Limiter instances (§12.1)', () => {
  const clusterSecret = crypto.randomBytes(32);
  const edgeAKey = Limiter.deriveSessionKey(clusterSecret, '203.0.113.9');
  const edgeBKey = Limiter.deriveSessionKey(clusterSecret, '203.0.113.9');
  const r = encodeReceipt({ window: 1, spent: 4, blockedUntil: 0, nonce: 1 });
  assert.ok(verifyReceipt(r, signReceipt(r, edgeAKey), edgeBKey));
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
t('LRU evicts under byte pressure, tracks savedComputeMs, and skips oversized items', () => {
  const c = new H4Cache({ maxBytes: 500 });
  for (let i = 0; i < 20; i++) c.set('k' + i, { data: 'x'.repeat(50) }, { computeMs: 12 });
  assert.ok(c.bytes <= 500);
  const lastHit = c.get('k19');
  assert.ok(lastHit);
  assert.equal(c.stats.savedComputeMs, 12);
  assert.equal(c.set('huge', { data: 'y'.repeat(1000) }), null);
  assert.ok(c.bytes <= 500);
  assert.notEqual(hashKey('a\u0000b', 'c'), hashKey('a', 'b\u0000c'));
});
t('stale entries are served under high pressure instead of recomputing', () => {
  const c = new H4Cache({ pressure: () => 200 });
  c.set('k', { v: 1 }, { ttlMs: 1 });
  const e = c.get('k', Date.now() + 100);
  assert.equal(e.stale, true);
});

console.log('\n── end-to-end behaviour & security (§8)');
const mkRoute = (calls) => async ({ path, method }) => {
  calls.n++;
  if (path === '/expensive') { await new Promise((r) => setTimeout(r, 20)); return { status: 200, body: { path, answer: 42 }, cost: 30, tokens: 1200, ttlMs: 5000 }; }
  return { status: 200, body: { path, method }, cost: 1, ttlMs: 5000 };
};
const mkReq = (o = {}) => ({
  headers: o.headers ?? [[':method', o.method ?? 'GET'], [':path', o.path ?? '/x'], ['h4-agent', o.agent ?? 'bot']],
  intent: { mode: o.mode ?? 0, idem: o.idem ?? '', deadlineMs: o.deadlineMs ?? 30_000, costCeiling: o.ceiling ?? 0, maxShape: 0, dedup: o.dedup ?? '' },
  cost: { predicted: 0, costClass: o.class ?? 0, effortBits: 0, budgetRemaining: 0, value: o.value ?? 0, tokenBudget: 0 },
  cap: o.cap, rate: o.rate, effortNonce: o.effortNonce, peer: o.peer ?? '1.2.3.4', sessionKey: o.sessionKey, body: o.body,
});

ta('issued maxSubs buys a proportional aggregate quota (operator fan-out)', async () => {
  const { reg, privateKey } = setupKey();
  const root = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ | CAPS.DELEGATE, expiresAt: Math.floor(Date.now() / 1000) + 60, maxSubs: 20 });
  const mk = (i) => attenuate(root, { caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60, subs: i });
  const s = new H4Server({ registry: reg, routes: { '/x': mkRoute({ n: 0 }) }, limiter: new Limiter({ budget: 5, windowMs: 10_000 }) });
  let served = 0;
  for (let i = 0; i < 20; i++) {
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
  assert.equal((await s.handle(mkReq({ agent: 'v-1', peer: '8.8.8.8' }))).reject, undefined);
});
ta('PoE redemption under aggregate net pressure succeeds without infinite recursion (§6.4)', async () => {
  const s = new H4Server({
    routes: { '/x': mkRoute({ n: 0 }) },
    limiter: new Limiter({ budget: 1, windowMs: 10_000, netMultiplier: 1, pressure: () => 160 }),
  });
  const now = 120_000;
  await s.handle(mkReq({ agent: 'a1', peer: '7.7.7.7' }), now);
  const priced = await s.handle(mkReq({ agent: 'a2', peer: '7.7.7.7' }), now);
  assert.equal(priced.reject.code, fr.REJECT.EFFORT_REQUIRED);
  const ch = Buffer.from(priced.reject.detail, 'base64url');
  const { nonce } = solvePoE(ch, priced.reject.difficulty);
  const ok = await s.handle(mkReq({ agent: 'a2', peer: '7.7.7.7', effortNonce: nonce }), now);
  assert.equal(ok.reject, undefined);
  assert.equal(ok.result.status, 200);
  // Replaying the same PoE nonce immediately fails
  await s.handle(mkReq({ agent: 'a3', peer: '7.7.7.7' }), now);
  const replay = await s.handle(mkReq({ agent: 'a2', peer: '7.7.7.7', effortNonce: nonce }), now);
  assert.ok(replay.reject);
});
ta('cross-tenant cache isolation blocks spoofed h4-tenant headers (§7)', async () => {
  const { reg, privateKey } = setupKey();
  const tokA = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60, tenant: 'acme' });
  const tokB = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60, tenant: 'globex' });
  const s = new H4Server({
    registry: reg,
    routes: { '/secret': async ({ identity }) => ({ status: 200, body: { owner: identity.tenant }, cost: 1, ttlMs: 10_000 }) },
  });
  const resA = await s.handle(mkReq({ path: '/secret', cap: { token: tokA } }));
  assert.equal(resA.result.cache, fr.CACHE.MISS);
  // Tenant B spoofs `h4-tenant: acme` in headers — must NOT hit Tenant A's cached response!
  const resB = await s.handle(mkReq({
    headers: [[':method', 'GET'], [':path', '/secret'], ['h4-tenant', 'acme']],
    cap: { token: tokB },
  }));
  assert.equal(resB.result.cache, fr.CACHE.MISS);
  const bodyB = [...fr.iterFrames(Buffer.concat(resB.frames))].find((f) => f.type === fr.F.DATA).payload.toString();
  assert.equal(JSON.parse(bodyB).owner, 'globex');
});
ta('anti-smuggling: duplicate pseudo-headers and prototype route names are rejected (§8)', async () => {
  const s = new H4Server({ routes: { '/x': mkRoute({ n: 0 }) } });
  const dup = await s.handle(mkReq({ headers: [[':method', 'GET'], [':path', '/x'], [':path', '/admin']] }));
  assert.equal(dup.reject.code, fr.REJECT.MALFORMED);
  const protoPath = await s.handle(mkReq({ headers: [[':method', 'GET'], [':path', 'toString']] }));
  assert.equal(protoPath.reject.code, fr.REJECT.MALFORMED);
  const trav = await s.handle(mkReq({ headers: [[':method', 'GET'], [':path', '/x/../admin']] }));
  assert.equal(trav.reject.code, fr.REJECT.MALFORMED);
});
ta('deadline_ms is enforced and emits REJECT.DEFERRED when exceeded (§3.3)', async () => {
  const s = new H4Server({
    routes: { '/slow': async () => { await new Promise((r) => setTimeout(r, 40)); return { status: 200, body: { ok: 1 } }; } },
  });
  const res = await s.handle(mkReq({ path: '/slow', deadlineMs: 10 }));
  assert.equal(res.reject.code, fr.REJECT.DEFERRED);
});
ta('idempotency key (intent.idem) prevents duplicate execution of POST mutations (§3.3)', async () => {
  let charges = 0;
  const s = new H4Server({
    routes: { 'POST /pay': async () => ({ status: 200, body: { chargeId: ++charges }, cost: 10 }) },
  });
  const a = await s.handle(mkReq({ path: '/pay', method: 'POST', mode: fr.MODE.MUTATE, idem: 'ord-99' }));
  const b = await s.handle(mkReq({ path: '/pay', method: 'POST', mode: fr.MODE.MUTATE, idem: 'ord-99' }));
  assert.equal(charges, 1);
  assert.equal(b.result.cache, fr.CACHE.MEMO);
  assert.equal(b.result.costActual, 1);
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
  const res = await s.handle(mkReq({ path: '/expensive', method: 'POST', ceiling: 1 }));
  assert.equal(res.reject.code, fr.REJECT.COST_REFUSED);
  assert.equal(calls.n, 0, 'handler must not run');
});
ta('capability scope is enforced before the handler runs (including prefix sibling)', async () => {
  const { reg, privateKey } = setupKey();
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/x': mkRoute(calls), '/v1/items-secret': mkRoute(calls) }, registry: reg });
  const tok = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60, scope: '/v1/items' });
  assert.equal((await s.handle(mkReq({ path: '/x', cap: { token: tok } }))).reject.code, fr.REJECT.SCOPE_DENIED);
  assert.equal((await s.handle(mkReq({ path: '/v1/items-secret', cap: { token: tok } }))).reject.code, fr.REJECT.SCOPE_DENIED);
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
ta('client refuses work whose predicted cost exceeds its value, and learns from costAsym (§3.5)', async () => {
  const c = new H4Client();
  const d = c.shouldSend({ path: '/x', method: 'POST', intent: { maxShape: 50 }, cost: {}, worth: 2 });
  assert.equal(d.send, false); assert.equal(d.reason, 'not-worth-it');

  // Observe an unexpectedly expensive GET route (`costAsym = +50`) and verify prediction adapts
  const before = c.predictCost({ path: '/heavy-get', method: 'GET' });
  c.observe(fr.encodeResult({ status: 200, costActual: 51, cache: fr.CACHE.MISS, costAsym: 50 }), { path: '/heavy-get', method: 'GET' });
  const after = c.predictCost({ path: '/heavy-get', method: 'GET' });
  assert.ok(after > before, `expected learned cost ${after} > ${before}`);
});
ta('server rate policy is adopted by the client', async () => {
  const c = new H4Client();
  c.observe(Buffer.concat([fr.encodeRate({ pressure: 180, budgetRemaining: 0, blockUntilMs: Date.now() + 500 })]));
  const d = c.shouldSend({ path: '/x' });
  assert.equal(d.send, false);
  assert.equal(d.reason, 'self-rate-limited');
});
ta('retry storm: 100 identical expensive requests → 1 computation', async () => {
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/expensive': mkRoute(calls) }, limiter: new Limiter({ budget: 100000 }) });
  await Promise.all(Array.from({ length: 100 }, () => s.handle(mkReq({ path: '/expensive', dedup: 'storm' }))));
  assert.equal(calls.n, 1, `handler ran ${calls.n} times`);
  assert.ok(s.metrics.coalesced > 0);
});
ta('hostile client cannot bypass the server bucket by lying in its receipt', async () => {
  const key = Limiter.sessionKey();
  const calls = { n: 0 };
  const s = new H4Server({ routes: { '/expensive': mkRoute(calls) }, limiter: new Limiter({ budget: 10 }) });
  let served = 0, rejected = 0;
  for (let i = 0; i < 30; i++) {
    const r = encodeReceipt({ window: Math.floor(Date.now() / 10_000), spent: 0, blockedUntil: 0, nonce: i + 1 });
    const res = await s.handle(mkReq({ path: '/expensive', dedup: '', rate: { receipt: r, mac: signReceipt(r, key) }, sessionKey: key }));
    if (res.reject) rejected++; else served++;
  }
  assert.ok(rejected > 0, 'server must reject once its own bucket is empty');
});

console.log('\n── wire carrier & HTTP/1.1 + HTTP/2 gateway (§2, §10)');
function genSelfSignedTls() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'h4-test-'));
  try {
    const key = path.join(dir, 'k.pem'), crt = path.join(dir, 'c.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt,
      '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
    return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

ta('wire TLS 1.3 carrier: ALPN h4, cooperative receipts, >128KB chunked response, and malformed resilience', async () => {
  const tlsOpts = genSelfSignedTls();
  const bigPayload = 'Z'.repeat(150_000);
  const handler = new H4Server({
    routes: {
      'GET /big': async () => ({ status: 200, type: 'text/plain', body: bigPayload, cost: 2, ttlMs: 1000 }),
    },
  });
  const srv = createServer({ handler, tlsOptions: tlsOpts });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const conn = await connect({ port, tlsOptions: { rejectUnauthorized: false } });
  try {
    assert.equal(conn.alpnProtocol, 'h4');
    const client = new H4Client({ sessionKey: conn.sessionKey }).provision(conn.handshake.ratePolicy);
    assert.equal(client.shouldSend({ path: '/big', method: 'GET' }), null);
    const flight = client.build({ path: '/big', method: 'GET' });
    const res = await conn.request(flight.frames);
    const obs = client.observe(res.payload, { path: '/big', method: 'GET' });
    assert.equal(obs.result.status, 200);
    assert.equal(obs.body.length, 150_000);
    assert.equal(handler.limiter.stats.receiptsOk, 1);

    // Send garbage frame bytes on a valid bidi stream: server must reply REJECT.MALFORMED, not crash
    const bad = await conn.request(Buffer.from([0x00, 0x05, 0xff]));
    const badObs = client.observe(bad.payload);
    assert.equal(badObs.reject.code, fr.REJECT.MALFORMED);
  } finally {
    conn.close();
    srv.close();
  }
});

ta('HTTP/1.1 & HTTP/2 gateways translate capabilities, coalescing, and cost headers (§10)', async () => {
  const { reg, privateKey } = setupKey();
  const tok = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 60, scope: '/v1' });
  let runs = 0;
  const handler = new H4Server({
    registry: reg,
    requireCap: true,
    routes: {
      'GET /v1/data': async () => {
        runs++;
        await new Promise((r) => setTimeout(r, 15));
        return { status: 200, body: { ok: true, runs }, cost: 7, tokens: 128, ttlMs: 5000 };
      },
    },
  });

  // 1) HTTP/1.1 gateway
  const gw1 = createGateway({ handler, altSvcPort: 8443 });
  await new Promise((r) => gw1.listen(0, '127.0.0.1', r));
  const p1 = gw1.address().port;
  try {
    const unauth = await fetch(`http://127.0.0.1:${p1}/v1/data`);
    assert.equal(unauth.status, 401);

    const [r1, r2] = await Promise.all([0, 1].map(() =>
      fetch(`http://127.0.0.1:${p1}/v1/data`, {
        headers: { authorization: `Bearer ${tok.toString('base64url')}`, 'h4-dedup': 'g1' },
      })
    ));
    assert.equal(r1.status, 200);
    assert.equal(r2.status, 200);
    assert.equal(runs, 1, 'HTTP/1.1 gateway coalesced concurrent callers');
    assert.match(r1.headers.get('alt-svc') ?? '', /h4=":8443"/);
    assert.ok(r1.headers.get('h4-cost-actual'));
  } finally {
    gw1.close();
  }

  // 2) HTTP/2 gateway
  const gw2 = createH2Gateway({ handler, altSvcPort: 8443 });
  await new Promise((r) => gw2.listen(0, '127.0.0.1', r));
  const p2 = gw2.address().port;
  const h2Client = http2.connect(`http://127.0.0.1:${p2}`);
  try {
    const status = await new Promise((resolve, reject) => {
      const req = h2Client.request({
        ':method': 'GET',
        ':path': '/v1/data',
        authorization: `Bearer ${tok.toString('base64url')}`,
      });
      req.on('response', (headers) => resolve(headers[':status']));
      req.on('error', reject);
      req.end();
    });
    assert.equal(status, 200);
  } finally {
    h2Client.close();
    gw2.close();
  }
});

for (const { name, fn } of pending) {
  try { await fn(); pass++; console.log(`  ok   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); }
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
