#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// Zero-Code Sidecar Demo: H4 Reverse Proxy in front of ANY Backend (FastAPI/Go/vLLM)
//
// Proves how a Python / Go / vLLM server on localhost:8000 gets:
//   • 50 concurrent identical agent retries -> 1 single upstream LLM computation!
//   • Automatic DDoS rate-limiting & C11 Proof-of-Effort protection
//   • Zero changes to the backend code!
// ─────────────────────────────────────────────────────────────────────────────

import http from 'node:http';
import { createReverseProxy } from '../src/index.js';

// 1. Simulate a slow, expensive Python FastAPI / vLLM server ($0.05 per call)
let upstreamCalls = 0;
const fakeFastApi = http.createServer(async (req, res) => {
  upstreamCalls++;
  await new Promise((r) => setTimeout(r, 40)); // simulate 40ms GPU inference
  res.writeHead(200, { 'content-type': 'application/json', 'h4-cost': '25' });
  res.end(JSON.stringify({ answer: '42', upstreamCallNumber: upstreamCalls }));
});
await new Promise((r) => fakeFastApi.listen(0, '127.0.0.1', r));
const upstreamPort = fakeFastApi.address().port;

// 2. Put H4 Reverse Proxy in front of it (same as `npx http4 proxy --upstream ...`)
const { httpGateway, h4Server } = createReverseProxy({
  upstream: `http://127.0.0.1:${upstreamPort}`,
  budget: 500,
  defaultTtlMs: 5_000,
});
await new Promise((r) => httpGateway.listen(0, '127.0.0.1', r));
const proxyPort = httpGateway.address().port;

// 3. Fire 50 concurrent retry-storm POST requests with the same `h4-dedup` key!
const storm = Array.from({ length: 50 }, () =>
  fetch(`http://127.0.0.1:${proxyPort}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'h4-dedup': 'prompt-hash-abc' },
    body: JSON.stringify({ prompt: 'Explain QUIC in one sentence' }),
  }).then((r) => r.json())
);

const answers = await Promise.all(storm);
console.log(`[sidecar] 50 concurrent agent retries completed!`);
console.log(`[sidecar] Actual upstream GPU/FastAPI executions: ${upstreamCalls} (saved ${50 - upstreamCalls} duplicate LLM calls!)`);
console.log(`[sidecar] Coalesced in-flight count: ${h4Server.stats().coalesced}, all 50 got answer="${answers[0].answer}"`);

httpGateway.close();
fakeFastApi.close();
