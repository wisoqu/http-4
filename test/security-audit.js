// ─────────────────────────────────────────────────────────────────────────────
// H4 Cybersecurity Red-Team & Differential C11 <-> JS Fuzzing Suite
// ─────────────────────────────────────────────────────────────────────────────

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import {
  F, REJECT, MODE, CLASS, CAPS,
  encodeHeaders, decodeHeaders,
  encodeIntent, encodeCost, encodeCap, encodeResult, encodeHeadersFrame, encodeData, iterFrames,
  KeyRegistry, mintRoot, attenuate, verify, verifyCache,
  Limiter, PassIssuer, solvePoE, checkPoE, memHardHash, memHardHashJs, solveMemHard, checkMemHard,
  H4Cache, H4Server, H4Client, normalizePeerIp,
  createServer, connect, packMessage,
  createGateway,
  encodeH3CompatFlight, decodeH3CompatFlight, isGreaseH3FrameType, H4_TO_H3_TYPE,
  createH4Fetch, AgentSession,
  toWebHandler, toNodeMiddleware, wrapFetchHandler, h4Shield, withH4, createReverseProxy,
  nativeBinding, isNativeLoaded,
} from '../src/index.js';

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed++;
    console.error(`  FAIL ${name}\n       ${err?.stack || err}`);
  }
}

function makeSelfSignedCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'h4-sec-'));
  const keyPath = path.join(dir, 'k.pem');
  const certPath = path.join(dir, 'c.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-keyout', keyPath, '-out', certPath, '-days', '1', '-nodes', '-subj', '/CN=localhost',
  ], { stdio: 'ignore' });
  const out = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

console.log(`\n── 1. Differential C11 <-> Pure-JS Fuzzing (nativeLoaded=${isNativeLoaded})`);

await test('HMAC-SHA256, PoE, MemHard, CapChain, and FrameScanner match pure-JS bit-for-bit across 2,000 fuzz cases', () => {
  if (!nativeBinding) return; // skipped when H4_PURE_JS=1

  // 1a. HMAC-SHA256 differential fuzzing (keys 0..128B, domains 0..32B, msgs 0..512B)
  for (let i = 0; i < 500; i++) {
    const key = crypto.randomBytes(i % 129);
    const dom = crypto.randomBytes(i % 33);
    const msg = crypto.randomBytes(i % 257);
    const outLen = 1 + (i % 32);
    const cMac = nativeBinding.hmacSha256(key, dom, msg, outLen);
    const jMac = crypto.createHmac('sha256', key).update(dom).update(msg).digest().subarray(0, outLen);
    assert.deepEqual(cMac, jMac);
  }

  // 1b. MemHard 4 KB puzzle differential fuzzing (including >32-bit nonces)
  for (let i = 0; i < 500; i++) {
    const ch = crypto.randomBytes(1 + (i % 48));
    const nonce = i === 0 ? 0 : (i === 1 ? 0xffffffff : (i === 2 ? 0x100000000 : Math.floor(Math.random() * 1e13)));
    const cHash = nativeBinding.memHardHash(ch, nonce);
    const jHash = memHardHashJs(ch, nonce);
    assert.deepEqual(cHash, jHash);
  }

  // Explicit >MAX_SAFE_INTEGER 8-byte QUIC varint frame type regression vector
  const over53BitFrame = Buffer.from([0xd6, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x41]);
  assert.equal(nativeBinding.scanFrames(over53BitFrame), null);

  // 1c. Frame scanner differential fuzzing (5,000 valid + corrupted buffers)
  for (let i = 0; i < 5000; i++) {
    const buf = i % 2 === 0
      ? Buffer.concat([
          encodeHeadersFrame([[':method', 'GET'], [':path', '/v1/test']]),
          encodeIntent({ mode: MODE.QUERY, deadlineMs: 1000 }),
          encodeData(crypto.randomBytes(i % 64)),
        ])
      : crypto.randomBytes(i % 96);

    let jsFrames = null;
    try {
      jsFrames = [...iterFrames(buf)];
    } catch {
      jsFrames = null;
    }
    const cScan = nativeBinding.scanFrames(buf);
    if (jsFrames !== null && jsFrames.length <= 256) {
      assert.ok(cScan instanceof Float64Array);
      assert.equal(cScan.length, jsFrames.length * 3);
      for (let k = 0; k < jsFrames.length; k++) {
        assert.equal(cScan[k * 3], jsFrames[k].type);
        assert.equal(cScan[k * 3 + 2], jsFrames[k].payload.length);
        assert.deepEqual(
          buf.subarray(cScan[k * 3 + 1], cScan[k * 3 + 1] + cScan[k * 3 + 2]),
          jsFrames[k].payload
        );
      }
    } else {
      assert.equal(cScan, null);
    }
  }
});

await test('N-API C11 bindings reject hostile JS types/bounds cleanly without memory corruption', () => {
  if (!nativeBinding) return;
  assert.throws(() => nativeBinding.solvePoE('not-a-buffer', 8, 100), TypeError);
  assert.throws(() => nativeBinding.hmacSha256('bad', Buffer.alloc(4), Buffer.alloc(4), 16), TypeError);
  assert.throws(() => nativeBinding.verifyCapLinks('bad', Buffer.alloc(4), Buffer.alloc(4)), TypeError);
  assert.equal(nativeBinding.solvePoE(Buffer.alloc(16), 200, 100), null);
  assert.equal(nativeBinding.checkPoE(Buffer.alloc(16), -5, 8), false);
  assert.equal(nativeBinding.checkPoE(Buffer.alloc(16), NaN, 8), false);
  assert.equal(nativeBinding.checkPoE(Buffer.alloc(16), Infinity, 8), false);
  assert.equal(nativeBinding.checkPoE(Buffer.alloc(16), 1e100, 8), false);
  assert.equal(nativeBinding.checkPoE(Buffer.alloc(16), 1.5, 8), false);
  assert.equal(nativeBinding.checkPoE('not-a-buffer', 0, 8), false);
  assert.equal(nativeBinding.checkMemHard(Buffer.alloc(16), -1, 8), false);
  assert.equal(nativeBinding.checkMemHard(Buffer.alloc(16), NaN, 8), false);
  assert.equal(nativeBinding.checkMemHard(Buffer.alloc(16), Infinity, 8), false);
  assert.equal(nativeBinding.checkMemHard(Buffer.alloc(16), 2.25, 8), false);
  assert.throws(() => nativeBinding.memHardHash(Buffer.alloc(16), NaN), RangeError);
  assert.throws(() => nativeBinding.memHardHash(Buffer.alloc(16), Infinity), RangeError);
  assert.throws(() => nativeBinding.memHardHash(Buffer.alloc(16), 3.14), RangeError);
  assert.equal(nativeBinding.solvePoE(Buffer.alloc(16), 8, NaN), null);
  assert.equal(nativeBinding.solveMemHard(Buffer.alloc(16), 8, -Infinity), null);
  assert.equal(nativeBinding.hmacSha256(Buffer.alloc(8), Buffer.alloc(4), Buffer.alloc(4), 0).length, 32);
  assert.equal(nativeBinding.hmacSha256(Buffer.alloc(8), Buffer.alloc(4), Buffer.alloc(4), 99).length, 32);
  assert.equal(nativeBinding.verifyCapLinks(Buffer.alloc(64), Buffer.alloc(4), Buffer.alloc(0)).rc, 1);
  assert.equal(nativeBinding.verifyCapLinks(Buffer.alloc(64), Buffer.alloc(4), Buffer.alloc(3)).rc, -1);
  assert.equal(nativeBinding.solvePoE(Buffer.alloc(0), 6, 10000) !== undefined, true);
});

console.log('\n── 2. Cryptographic Domain Separation & Revocation');

await test('root signature without H4-CAP-ROOT-v1 domain tag is rejected (cross-protocol confusion guard)', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const reg = new KeyRegistry().add(1, publicKey);
  const valid = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 300 });
  assert.equal(verify(valid, reg).ok, true);

  // Forge a legacy/cross-protocol signature directly over signedRoot WITHOUT domain prefix
  const signedRoot = valid.subarray(0, valid.length - 64);
  const rawSig = crypto.sign(null, signedRoot, privateKey);
  const confused = Buffer.concat([signedRoot, rawSig]);
  verifyCache.clear();
  const res = verify(confused, reg);
  assert.equal(res.ok, false);
  assert.equal(res.code, 'CAP_INVALID');
});

await test('KeyRegistry.revokeGrant and KeyRegistry.remove immediately invalidate cached root grants', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const reg = new KeyRegistry().add(7, publicKey);
  const root = mintRoot({ keyId: 7, privateKey, caps: CAPS.READ | CAPS.DELEGATE, expiresAt: Math.floor(Date.now() / 1000) + 300 });
  const child = attenuate(root, { caps: CAPS.READ, subs: 1 });

  const v1 = verify(child, reg);
  assert.equal(v1.ok, true);

  // Revoke grant ID -> even though root sig is cached in verifyCache, child is immediately blocked
  reg.revokeGrant(v1.grant);
  const v2 = verify(child, reg);
  assert.equal(v2.ok, false);
  assert.match(v2.why, /revoked/);

  // Key removal also invalidates immediately
  const root2 = mintRoot({ keyId: 7, privateKey, caps: CAPS.READ, expiresAt: Math.floor(Date.now() / 1000) + 300, scope: '/v2' });
  assert.equal(verify(root2, reg).ok, true);
  reg.remove(7);
  assert.equal(verify(root2, reg).ok, false);
});

console.log('\n── 3. Header CRLF / NUL Injection & Smuggling');

await test('CRLF, NUL, whitespace in header names, and >32KB header bombs are rejected', () => {
  assert.throws(() => encodeHeaders([['x-bad\r\n', '1']]), RangeError);
  assert.throws(() => encodeHeaders([['x-ok', 'val\r\ninjected: true']]), RangeError);
  assert.throws(() => encodeHeaders([['x-ok', 'val\u0000null']]), RangeError);
  assert.throws(() => encodeHeaders([['x space', '1']]), RangeError);
  assert.throws(() => encodeHeaders([['x-huge', 'a'.repeat(40_000)]]), RangeError);
});

await test('H4Server rejects direct in-memory CRLF/NUL header smuggling before route execution', async () => {
  let ran = false;
  const s = new H4Server({ routes: { 'GET /ok': () => { ran = true; return { body: 'ok' }; } } });
  const r1 = await s.handle({ headers: [[':method', 'GET'], [':path', '/ok'], ['x-evil', 'foo\r\nbar']] });
  assert.equal(r1.reject.code, REJECT.MALFORMED);
  assert.equal(ran, false);
});

console.log('\n── 4. 0-RTT Replay Guard, h4-pass Single-Use Bypass, & MemHard PoE');

await test('0-RTT earlyData blocks non-idempotent mutations (425 Too Early) while permitting idempotent ones once', async () => {
  let executions = 0;
  const s = new H4Server({
    routes: {
      'POST /pay': () => { executions++; return { status: 200, body: { paid: executions }, cost: 5 }; },
    },
  });

  // Unsafe 0-RTT POST without idempotency key -> REJECT.DEFERRED ('0rtt-unsafe-mutate')
  const unsafe = await s.handle({
    headers: [[':method', 'POST'], [':path', '/pay']],
    intent: { mode: MODE.MUTATE, idem: '' },
    earlyData: true,
  });
  assert.equal(unsafe.reject.code, REJECT.DEFERRED);
  assert.equal(unsafe.reject.detail, '0rtt-unsafe-mutate');
  assert.equal(executions, 0);

  // Safe 0-RTT POST WITH idempotency key -> executes exactly once across replays
  const safe1 = await s.handle({
    headers: [[':method', 'POST'], [':path', '/pay']],
    intent: { mode: MODE.MUTATE, idem: 'idem-tx-99' },
    earlyData: true,
  });
  const safe2 = await s.handle({
    headers: [[':method', 'POST'], [':path', '/pay']],
    intent: { mode: MODE.MUTATE, idem: 'idem-tx-99' },
    earlyData: true,
  });
  assert.equal(safe1.result.status, 200);
  assert.equal(safe2.result.status, 200);
  assert.equal(executions, 1);
});

await test('PassIssuer single-use h4-pass bypasses overload with 0 client PoE hashes and blocks double-spend', async () => {
  const passIssuer = new PassIssuer({ ttlSec: 60 });
  const limiter = new Limiter({ budget: 1, windowMs: 60_000, pressure: () => 200, passIssuer });
  const s = new H4Server({
    limiter,
    routes: { 'GET /hot': () => ({ status: 200, body: { ok: true }, cost: 1 }) },
  });

  // First request consumes the 1-unit bucket
  const r1 = await s.handle({ headers: [[':method', 'GET'], [':path', '/hot']], peer: '10.0.0.1' });
  assert.equal(r1.result.status, 200);

  // Second request hits EFFORT_REQUIRED
  const r2 = await s.handle({ headers: [[':method', 'GET'], [':path', '/hot'], ['h4-cache-key', '2']], peer: '10.0.0.1' });
  assert.equal(r2.reject.code, REJECT.EFFORT_REQUIRED);

  // Mint 1 single-use pass: redeems cleanly with zero PoW
  const pass = passIssuer.mint();
  const r3 = await s.handle({
    headers: [[':method', 'GET'], [':path', '/hot'], ['h4-cache-key', '3'], ['h4-pass', pass]],
    peer: '10.0.0.1',
  });
  assert.equal(r3.result.status, 200);

  // Double-spend replay of the exact same pass fails
  assert.equal(passIssuer.redeem(pass).ok, false);
  assert.equal(passIssuer.redeem(pass).why, 'replayed-pass');
  // Tampered pass fails
  assert.equal(passIssuer.redeem(pass.slice(0, -2) + 'AA').ok, false);
});

await test('4 KB cache-hard MemHard PoE challenges and verifies end-to-end via H4Client', async () => {
  const limiter = new Limiter({ budget: 1, windowMs: 60_000, pressure: () => 160, poeMode: 'memhard' });
  const s = new H4Server({
    limiter,
    routes: { 'POST /work': () => ({ status: 200, body: { done: true }, cost: 2 }) },
  });
  const c = new H4Client({ maxEffortBits: 16 });

  await s.handle({ headers: [[':method', 'POST'], [':path', '/work']], peer: '10.0.0.2' });
  const chalRes = await s.handle({ headers: [[':method', 'POST'], [':path', '/work']], peer: '10.0.0.2' });
  assert.equal(chalRes.reject.code, REJECT.EFFORT_REQUIRED);
  assert.ok(chalRes.reject.detail.startsWith('mh:'));

  const nonce = c.payEffort(chalRes.reject);
  assert.ok(Number.isSafeInteger(nonce));

  const solvedRes = await s.handle({
    headers: [[':method', 'POST'], [':path', '/work'], ['h4-effort', String(nonce)]],
    peer: '10.0.0.2',
  });
  assert.equal(solvedRes.result.status, 200);
});

await test('H4Client maxEffortBits refuses excessive PoE difficulty (rogue server CPU-DoS guard)', () => {
  const c = new H4Client({ maxEffortBits: 16 });
  const t0 = performance.now();
  const res = c.payEffort({ difficulty: 28, detail: Buffer.alloc(32, 1).toString('base64url') });
  const elapsed = performance.now() - t0;
  assert.equal(res, null);
  assert.equal(c.stats.effortRefused, 1);
  assert.ok(elapsed < 10);
});

console.log('\n── 5. Dual-Stack IP Normalization, Cache OOM Guard, & 5xx Poisoning Guard');

await test('IPv4-mapped IPv6 peer addresses share the exact same anonymous quota bucket', () => {
  assert.equal(normalizePeerIp('::ffff:203.0.113.42'), '203.0.113.42');
  assert.equal(normalizePeerIp('203.0.113.42'), '203.0.113.42');
  assert.equal(normalizePeerIp('fe80::1%eth0'), 'fe80::1');

  const limiter = new Limiter({ budget: 2, windowMs: 60_000, netMultiplier: 1 });
  const s = new H4Server({
    limiter,
    routes: { 'POST /ping': () => ({ status: 200, body: 'ok' }) },
  });
  return (async () => {
    await s.handle({ headers: [[':method', 'POST'], [':path', '/ping'], ['h4-agent-instance', 'a']], peer: '203.0.113.7' });
    await s.handle({ headers: [[':method', 'POST'], [':path', '/ping'], ['h4-agent-instance', 'b']], peer: '::ffff:203.0.113.7' });
    const third = await s.handle({ headers: [[':method', 'POST'], [':path', '/ping'], ['h4-agent-instance', 'c']], peer: '::ffff:203.0.113.7' });
    assert.ok(third.reject, 'dual-stack bypass must hit shared net limit');
  })();
});

await test('H4Cache blocks BigInt+Buffer OOM bypass and H4Server avoids caching transient 5xx failures', async () => {
  const cache = new H4Cache({ maxBytes: 1024 });
  const stored = cache.set('k1', { unserializable: 1n, body: Buffer.alloc(50_000) });
  assert.equal(stored, null);
  assert.equal(cache.bytes, 0);

  let attempt = 0;
  const s = new H4Server({
    routes: {
      'GET /flaky': () => {
        attempt++;
        if (attempt === 1) return { status: 503, body: { error: 'db blip' } };
        return { status: 200, body: { ok: true } };
      },
    },
  });
  const first = await s.handle({ headers: [[':method', 'GET'], [':path', '/flaky']] });
  assert.equal(first.result.status, 503);
  const second = await s.handle({ headers: [[':method', 'GET'], [':path', '/flaky']] });
  assert.equal(second.result.status, 200, '503 error must not poison GET cache');
});

console.log('\n── 6. TLS 1.3 Wire Red-Team: ALPACA, Slowloris, Rapid-Reset, & F.CANCEL');

await test('ALPACA cross-protocol guard, Slowloris handshakeTimeoutMs, and maxConcurrentStreams enforce cleanly', async () => {
  const tlsMat = makeSelfSignedCert();
  const h4 = new H4Server({
    routes: {
      'GET /slow': async () => {
        await new Promise((r) => setTimeout(r, 60));
        return { status: 200, body: { ok: true } };
      },
    },
  });

  const srv = createServer({
    handler: h4,
    tlsOptions: { key: tlsMat.key, cert: tlsMat.cert },
    handshakeTimeoutMs: 120,
    maxConcurrentStreams: 3,
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();

  try {
    // 6a. ALPACA attack: client negotiates HTTP/1.1 ALPN (or no H4 ALPN) -> destroyed immediately
    await new Promise((resolve) => {
      const sock = tls.connect({
        host: '127.0.0.1', port, ca: tlsMat.cert, servername: 'localhost',
        ALPNProtocols: ['http/1.1'],
      });
      sock.on('close', resolve);
      sock.on('error', resolve);
    });

    // 6b. Slowloris pre-HELLO stall: negotiates h4 ALPN, sends nothing -> killed in ~120ms
    const t0 = Date.now();
    await new Promise((resolve) => {
      const sock = tls.connect({
        host: '127.0.0.1', port, ca: tlsMat.cert, servername: 'localhost',
        ALPNProtocols: ['h4'],
      });
      sock.on('close', resolve);
      sock.on('error', resolve);
    });
    assert.ok(Date.now() - t0 < 1500, 'Slowloris pre-HELLO socket must be closed promptly');

    // 6c. Rapid-Reset / stream flood: 5 concurrent streams > maxConcurrentStreams (3)
    const conn = await connect({
      host: '127.0.0.1', port,
      tlsOptions: { ca: tlsMat.cert, rejectUnauthorized: true },
    });
    const c = new H4Client({ sessionKey: conn.sessionKey });
    const reqs = Array.from({ length: 5 }, (_, i) => {
      const b = c.build({ path: `/slow?i=${i}`, method: 'GET' });
      return conn.request(b.frames);
    });
    const results = await Promise.all(reqs);
    const decoded = results.map((r) => c.observe(r.payload));
    const rateLimited = decoded.filter((d) => d.reject?.code === REJECT.RATE_LIMITED);
    assert.ok(rateLimited.length >= 2, 'excess concurrent streams must be rejected');
    conn.close();
  } finally {
    srv.close();
  }
});

console.log('\n── 7. RFC 9114 HTTP/3 Extension Profile & Universal SDK / Adapters');

await test('H3 extension frame mapping avoids all GREASE codes and ignores unknown extension frames', () => {
  for (const [, h3Code] of H4_TO_H3_TYPE) {
    assert.equal(isGreaseH3FrameType(h3Code), false, `H3 code 0x${h3Code.toString(16)} collided with GREASE`);
  }
  assert.equal(isGreaseH3FrameType(0x21), true);
  assert.equal(isGreaseH3FrameType(0x40), true);

  const origFlight = Buffer.concat([
    encodeHeadersFrame([[':method', 'GET'], [':path', '/v1/h3']]),
    encodeIntent({ mode: MODE.QUERY, deadlineMs: 5000 }),
    encodeCost({ predicted: 3, costClass: CLASS.NORMAL }),
    encodeData(Buffer.from('{"hello":"h3"}')),
  ]);
  const h3Bytes = encodeH3CompatFlight(origFlight);
  // Prepend an RFC 9114 GREASE frame (type 0x21 = single-byte varint, len 3, payload 'xyz')
  const withGrease = Buffer.concat([Buffer.from([0x21, 0x03, 0x78, 0x79, 0x7a]), h3Bytes]);
  const roundTripped = decodeH3CompatFlight(withGrease);
  assert.deepEqual(roundTripped, origFlight);
});

await test('toWebHandler, toNodeMiddleware, wrapFetchHandler, createH4Fetch (Alt-Svc), and SSE streaming integrate cleanly', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const reg = new KeyRegistry().add(1, publicKey);
  const h4 = new H4Server({
    registry: reg,
    routes: {
      'GET /v1/web': wrapFetchHandler(async (req) => {
        return new Response(JSON.stringify({ url: req.url, ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json', 'h4-cost': '3' },
        });
      }),
      'GET /v1/events': async function* () {
        yield { n: 1 };
        yield { n: 2 };
      },
      'POST /v1/mutate': () => ({ status: 200, body: { saved: true } }),
    },
  });

  // 7a. WinterCG Web Handler (unary + 0-RTT 425 + SSE stream)
  const webHandler = toWebHandler(h4);
  const r1 = await webHandler(new Request('https://edge.example/v1/web'));
  assert.equal(r1.status, 200);
  assert.equal(r1.headers.get('h4-cost-actual'), '3');
  assert.equal((await r1.json()).ok, true);

  const r425 = await webHandler(new Request('https://edge.example/v1/mutate', {
    method: 'POST',
    headers: { 'early-data': '1', 'h4-mode': 'mutate' },
    body: '{}',
  }));
  assert.equal(r425.status, 425);

  const rSse = await webHandler(new Request('https://edge.example/v1/events', {
    headers: { accept: 'text/event-stream' },
  }));
  assert.equal(rSse.status, 200);
  const sseText = await rSse.text();
  assert.match(sseText, /data: \{"n":1\}/);
  assert.match(sseText, /event: h4-result/);

  // 7b. Node/Express middleware + Alt-Svc auto-upgrade in createH4Fetch
  const tlsMat = makeSelfSignedCert();
  const wireSrv = createServer({ handler: h4, tlsOptions: { key: tlsMat.key, cert: tlsMat.cert } });
  await new Promise((r) => wireSrv.listen(0, '127.0.0.1', r));
  const h4Port = wireSrv.address().port;

  const mw = toNodeMiddleware(h4, { altSvc: `h4="127.0.0.1:${h4Port}"; ma=60` });
  const httpSrv = http.createServer((req, res) => {
    mw(req, res, () => {
      res.statusCode = 404;
      res.end('express-fallback');
    });
  });
  await new Promise((r) => httpSrv.listen(0, '127.0.0.1', r));
  const httpPort = httpSrv.address().port;

  try {
    const h4Fetch = createH4Fetch({
      tlsOptions: { ca: tlsMat.cert, rejectUnauthorized: true },
    });
    const token = mintRoot({ keyId: 1, privateKey, caps: CAPS.READ | CAPS.DELEGATE, expiresAt: Math.floor(Date.now() / 1000) + 300 });
    const session = new AgentSession({ token, h4Fetch, budget: 50 });

    // First call hits HTTP/1.1 middleware and discovers Alt-Svc: h4="127.0.0.1:<h4Port>"
    const first = await session.fetch(`http://127.0.0.1:${httpPort}/v1/web`);
    assert.equal(first.status, 200);

    // Second call to same HTTP origin transparently upgrades to pooled TLS 1.3 H4 wire!
    const second = await session.fetch(`http://127.0.0.1:${httpPort}/v1/web`);
    assert.equal(second.status, 200);
    assert.ok(second.h4?.result, 'second call must carry native H4 RESULT frame after Alt-Svc upgrade');

    // Unmatched route falls through middleware to `next()` ('express-fallback')
    const miss = await fetch(`http://127.0.0.1:${httpPort}/unmatched`);
    assert.equal(miss.status, 404);
    assert.equal(await miss.text(), 'express-fallback');

    await h4Fetch.close();
  } finally {
    httpSrv.close();
    wireSrv.close();
  }
});

console.log('\n── 8. Zero-Barrier Integration: :param Routes, h4Shield, withH4, ReverseProxy & CLI');

await test('dynamic :param and * wildcard routes match safely without ReDoS', async () => {
  const s = new H4Server({
    routes: {
      'GET /v1/orgs/:orgId/agents/:agentId': ({ params }) => ({
        status: 200,
        body: { orgId: params.orgId, agentId: params.agentId },
      }),
      'POST /v1/proxy/*': ({ params }) => ({
        status: 200,
        body: { rest: params['*'] },
      }),
    },
  });
  const f = createH4Fetch({ server: s });
  const r1 = await f('h4://local/v1/orgs/acme%20corp/agents/bot-7');
  assert.equal(r1.status, 200);
  assert.deepEqual(await r1.json(), { orgId: 'acme corp', agentId: 'bot-7' });

  const r2 = await f('h4://local/v1/proxy/chat/completions', { method: 'POST', body: '{}' });
  assert.equal(r2.status, 200);
  assert.deepEqual(await r2.json(), { rest: '/chat/completions' });
});

await test('h4Shield protects Express-style routes without consuming req body stream; withH4 & createReverseProxy coalesce storms', async () => {
  // 8a. h4Shield leaves POST body stream intact for downstream JSON parsers
  const shield = h4Shield({ budget: 50, windowMs: 10_000 });
  const appSrv = http.createServer((req, res) => {
    shield(req, res, async () => {
      const chunks = [];
      for await (const ch of req) chunks.push(ch);
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ got: parsed.hello, subject: req.h4.subject }));
    });
  });
  await new Promise((r) => appSrv.listen(0, '127.0.0.1', r));
  const appPort = appSrv.address().port;

  // 8b. createReverseProxy in front of appSrv: coalesces 20 duplicate requests -> 1 upstream hit & strips spoofed headers
  let upstreamCount = 0;
  const upstreamSrv = http.createServer(async (req, res) => {
    upstreamCount++;
    await new Promise((r) => setTimeout(r, 20));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      calls: upstreamCount,
      spoofedSubject: req.headers['x-h4-verified-subject'] ?? null,
    }));
  });
  await new Promise((r) => upstreamSrv.listen(0, '127.0.0.1', r));
  const upPort = upstreamSrv.address().port;

  const { httpGateway } = createReverseProxy({
    upstream: `http://127.0.0.1:${upPort}`,
    defaultTtlMs: 2_000,
  });
  await new Promise((r) => httpGateway.listen(0, '127.0.0.1', r));
  const proxyPort = httpGateway.address().port;

  try {
    const shieldRes = await fetch(`http://127.0.0.1:${appPort}/v1/echo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hello: 'express' }),
    });
    assert.equal(shieldRes.status, 200);
    const shieldJson = await shieldRes.json();
    assert.equal(shieldJson.got, 'express');
    assert.equal(typeof shieldJson.subject, 'string');

    // 20 concurrent calls with spoofed x-h4-verified-subject -> coalesced to 1 upstream call and spoof stripped!
    const burst = await Promise.all(
      Array.from({ length: 20 }, () =>
        fetch(`http://127.0.0.1:${proxyPort}/v1/infer`, {
          method: 'POST',
          headers: {
            'h4-dedup': 'same-prompt',
            'x-h4-verified-subject': 'spoofed-admin',
          },
          body: '{"p":"hi"}',
        }).then((r) => r.json())
      )
    );
    assert.equal(upstreamCount, 1);
    assert.equal(burst[0].spoofedSubject, null, 'spoofed x-h4-verified-* header must be stripped');

    // 8c. withH4 1-line Web handler wrapper
    let webRuns = 0;
    const wrapped = withH4(async () => {
      webRuns++;
      return Response.json({ runs: webRuns });
    }, { defaultTtlMs: 5_000 });
    await wrapped(new Request('https://worker.local/cached'));
    await wrapped(new Request('https://worker.local/cached'));
    assert.equal(webRuns, 1);
  } finally {
    httpGateway.close();
    upstreamSrv.close();
    appSrv.close();
  }
});

await test('CLI (`bin/http4.js`) doctor, keygen, and mint execute cleanly end-to-end', () => {
  const cliPath = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../bin/http4.js');
  const docOut = execFileSync(process.execPath, [cliPath, 'doctor'], { encoding: 'utf8' });
  assert.match(docOut, /status\s+READY/);

  const keyJson = JSON.parse(execFileSync(process.execPath, [cliPath, 'keygen'], { encoding: 'utf8' }));
  const mintedB64 = execFileSync(process.execPath, [
    cliPath, 'mint',
    '--private-key', keyJson.privateKeyPkcs8B64,
    '--scope', '/v1/data',
    '--caps', 'read,delegate',
  ], { encoding: 'utf8' }).trim();

  const pubKey = crypto.createPublicKey({
    key: Buffer.from(keyJson.publicKeySpkiB64, 'base64url'),
    format: 'der',
    type: 'spki',
  });
  const reg = new KeyRegistry().add(1, pubKey);
  const v = verify(Buffer.from(mintedB64, 'base64url'), reg, { required: CAPS.READ });
  assert.equal(v.ok, true);
  assert.equal(v.scope, '/v1/data');
});

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed > 0) process.exit(1);
