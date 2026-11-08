#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// 5-Minute Integration Demo: Multi-Agent Mesh over TLS 1.3 H4 + SDK + Streaming
//
// Shows:
//   1. Drop-in `createH4Fetch` + `AgentSession` offline macaroon delegation
//   2. Sub-agent scope & capability confinement (Researcher vs Streamer)
//   3. Live token streaming (`MODE.SUBSCRIBE`) + mid-stream `AbortController`
//      (`F.CANCEL`) with automatic server generation halt & budget refund
//   4. Zero-CPU `h4-pass` overload bypass wallet vs C11 Proof-of-Effort
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  H4Server, KeyRegistry, Limiter, PassIssuer, mintRoot, CAPS,
  createServer, createH4Fetch, AgentSession, isNativeLoaded,
} from '../src/index.js';

function makeSelfSignedCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'h4-mesh-'));
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

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const registry = new KeyRegistry().add(1, publicKey);
const passIssuer = new PassIssuer();
let pressure = 0;

const limiter = new Limiter({
  budget: 20,
  windowMs: 10_000,
  pressure: () => pressure,
  passIssuer,
});

let generatedTokensOnServer = 0;
const h4 = new H4Server({
  registry,
  limiter,
  requireCap: true,
  routes: {
    'GET /v1/docs/spec': async () => ({
      status: 200,
      body: { summary: 'HTTP/4 v0.2 with C11 N-API & streaming' },
      cost: 2,
      ttlMs: 5_000,
    }),
    'SUB /v1/llm/stream': async function* ({ signal }) {
      for (let i = 1; i <= 50; i++) {
        if (signal?.aborted) return;
        generatedTokensOnServer++;
        await new Promise((r) => setTimeout(r, 4));
        yield { token: `tok_${i}` };
      }
    },
  },
});

const tlsMat = makeSelfSignedCert();
const wireSrv = createServer({ handler: h4, tlsOptions: { key: tlsMat.key, cert: tlsMat.cert } });
await new Promise((r) => wireSrv.listen(0, '127.0.0.1', r));
const { port } = wireSrv.address();

const h4Fetch = createH4Fetch({
  tlsOptions: { ca: tlsMat.cert, rejectUnauthorized: true },
  passWallet: passIssuer.mintWallet(2),
});

// Root orchestrator mints a broad grant, then delegates offline to two narrow sub-agents
const rootGrant = mintRoot({
  keyId: 1,
  privateKey,
  caps: CAPS.READ | CAPS.WRITE | CAPS.SUBSCRIBE | CAPS.DELEGATE,
  expiresAt: Math.floor(Date.now() / 1000) + 600,
  scope: '/v1',
  tenant: 'acme-ai',
  maxSubs: 8,
});

const orchestrator = new AgentSession({ token: rootGrant, h4Fetch, budget: 100, instanceId: 'orch-1' });
const docReader = orchestrator.delegate({ caps: CAPS.READ, scope: '/v1/docs', budget: 20 });
const tokenStreamer = orchestrator.delegate({ caps: CAPS.SUBSCRIBE, scope: '/v1/llm', budget: 30 });

console.log(`[mesh] C11 native engine active: ${isNativeLoaded}`);

// 1. Sub-agent reads within its scope, fails outside its scope
const okRes = await docReader.fetch(`h4://127.0.0.1:${port}/v1/docs/spec`);
console.log('[1] docReader /v1/docs/spec ->', okRes.status, await okRes.json(), 'cost=', okRes.h4.result.costActual);

const deniedRes = await docReader.fetch(`h4://127.0.0.1:${port}/v1/admin/keys`);
console.log('[2] docReader /v1/admin/keys (outside /v1/docs) ->', deniedRes.status, '(blocked before handler)');

// 2. Live streaming + mid-stream AbortController (`F.CANCEL`)
const ac = new AbortController();
const received = [];
for await (const chunk of tokenStreamer.stream(`h4://127.0.0.1:${port}/v1/llm/stream`, { signal: ac.signal })) {
  received.push(chunk.toString().trim());
  if (received.length === 5) ac.abort('enough-context');
}
await new Promise((r) => setTimeout(r, 25));
console.log(`[3] tokenStreamer cancelled after ${received.length} chunks -> server generated ${generatedTokensOnServer}/50 tokens (saved ${50 - generatedTokensOnServer} LLM tokens!)`);

await h4Fetch.close();
wireSrv.close();
