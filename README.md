# HTTP/4 (`http4` v0.2.0)

> **[🇷🇺 Читать на русском (README.ru.md)](README.ru.md)** · **[Руководство по интеграции (docs/INTEGRATION.md)](docs/INTEGRATION.md)** · **[Protocol Spec](spec/http4.md)** · **[Security Model](SECURITY.md)**

[![CI & Sanitizers](https://github.com/wisoqu/http-4/actions/workflows/ci.yml/badge.svg)](https://github.com/wisoqu/http-4/actions/workflows/ci.yml)

**An agent-native, cost-aware, L7-DDoS-resistant evolution of HTTP** — with a **C11 Node-API accelerator**, **zero external dependencies**, and **1-command / 1-line drop-in integration** for existing HTTP/1.1, HTTP/2, HTTP/3, Python/FastAPI, Go, Express, and Edge apps.

---

## Why This Exists (What Broke Between Humans and AI Agents)

HTTP/1.1–3 were designed for a human clicking links at ~1 req/s. Autonomous AI agents broke three assumptions simultaneously:
1. **Retry storms burn GPU compute, not bytes:** 50 agents retrying the same slow LLM/tool call trigger 50 duplicate `$0.05` model runs.
2. **Sub-agent fan-out breaks OAuth/JWT:** an orchestrator spawning 8 narrow sub-agents either leaks its master API key or hammers an auth server on every hop.
3. **IP-based rate limits cause massive collateral damage:** 2,500 cloud/CGNAT agents behind 8 shared egress IPs get blanket-429'd together (`88%` false-positive drop rate in our benchmark).

`http4` fixes all three at the protocol & edge layer — **without requiring you to rewrite your backend**:
- **Singleflight Coalescing + Cost Ceilings (`INTENT` / `COST` / `RESULT`):** 100 identical in-flight requests execute **once**; callers declare `costCeiling` & `deadlineMs`; mid-stream `F.CANCEL` halts generation in `< 1 ms` and refunds unused budget.
- **Offline Macaroon Capabilities (`CAP`):** 1 Ed25519 verify per root grant (cached), then `~2 µs` offline `HMAC-SHA256-128` narrowing per sub-agent hop (`scope`, `caps`, `tenant`, `expiresAt`). Privilege escalation is mathematically impossible.
- **Client-Cooperative Limits + Priced Effort (`RATE` / `h4-pass` / C11 PoE):** honest clients self-account via signed receipts; overload triggers either zero-CPU single-use `h4-pass` redemption (`~2 µs`) or C11-accelerated `SHA-256` / 4 KB cache-hard `MemHard` Proof-of-Effort (`380 ns` server verify).

---

## Integrate in 60 Seconds (4 Ways — Pick Yours)

Install directly (Node.js ≥ 20, zero runtime npm dependencies; auto-compiles C11 N-API addon if `gcc`/`clang` is present, with seamless pure-JS fallback):

```bash
npm install github:wisoqu/http-4
```

### Option A: Zero-Code Sidecar Proxy (Python FastAPI, vLLM, Ollama, Go, Rust — Any Language)
Put `http4` in front of **any** existing HTTP backend in 1 command. Duplicate agent retries with `h4-dedup` coalesce into **1 upstream call**, and L7 floods hit C11 Proof-of-Effort before touching your app:

```bash
npx http4 proxy --upstream http://127.0.0.1:8000 --port 8080 --budget 200 --ttl-ms 5000
```

### Option B: 1 Line for Express / Fastify / Node `http`
Protects all existing routes without consuming `req` body streams (`express.json()`, `multer`, GraphQL, tRPC keep working untouched):

```js
import express from 'express';
import { h4Shield } from 'http4/adapters';

const app = express();
app.use(h4Shield({ budget: 200, windowMs: 10_000 })); // <- 1 line!
app.use(express.json());
app.post('/v1/chat', (req, res) => res.json({ subject: req.h4.subject, ok: true }));
app.listen(3000);
```

### Option C: 1 Line for Next.js App Router / Cloudflare Workers / Bun / Deno / Hono
Wraps any WinterCG `(Request) => Promise<Response>` handler with singleflight coalescing, tenant-isolated caching, 0-RTT `425` protection, and DDoS PoE:

```js
import { withH4 } from 'http4/adapters';

export default {
  fetch: withH4(async (req) => Response.json({ ok: true }), {
    budget: 200,
    defaultTtlMs: 5_000,
  }),
};
```

### Option D: Multi-Agent SDK (`fetch`-Compatible + 1-Line Offline Delegation & Streaming)

```js
import { createH4Fetch, AgentSession, CAPS } from 'http4';

const h4Fetch = createH4Fetch({ maxEffortBits: 20 }); // auto-upgrades via Alt-Svc!
const orchestrator = new AgentSession({ token: rootGrant, h4Fetch, budget: 100 });

// Spawn a strictly confined sub-agent offline in ~2 µs (0 auth-server round trips):
const docReader = orchestrator.delegate({
  caps: CAPS.READ,
  scope: '/v1/docs',
  budget: 25,
  delegable: false,
});

const res = await docReader.fetch('https://api.example.com/v1/docs/spec');

// Live token streaming with instant server-side halt & budget refund on abort:
const ac = new AbortController();
for await (const chunk of orchestrator.stream('h4://api.example.com:8443/v1/llm/stream', { signal: ac.signal })) {
  if (enoughContext(chunk)) ac.abort(); // sends F.CANCEL -> stops server LLM immediately
}
```

---

## Reproducible Benchmarks (2 vCPU Xeon · Node v22 · C11 N-API)

Every number below is measured on-box via `npm run bench` and `npm run attack`:

| Metric | Measured Result |
|---|---|
| Wire size: simple `GET` / 8-header agent call | **12 B** (`6.0×` smaller than H1) / **48 B** (`4.2×` smaller than H1) |
| Full binary request parse (`79 B` flight) | **667 ns** (`1.50 M ops/s`) |
| End-to-end `H4Server` serve (sync cache path) | **17.6 µs** (`56,900 req/s` per core) |
| Reject hostile / rate-limited request | **7.3 µs** (`2.4×` cheaper than serving) |
| PoE solver rate (`C11 N-API` vs `Pure JS`) | **2.99 M hashes/s** vs `0.49 M hashes/s` (**6.1× faster**) |
| Defender PoE verify (`SHA-256` / `4 KB MemHard`) | **380 ns** (`2.63 M/s`) / **2.94 µs** (`340 k/s`) — O(1) at any difficulty |
| Shared-CGNAT L7 Flood (`20,000` reqs, 500 attackers) | Honest agents served: **12.0% → 100.0%** · Attackers: **12.0% → 2.3%** |

---

## Verification & Sanitizer Suite

```bash
npx http4 doctor                         # check runtime & C11 N-API hash rate
npm test                                 # 62 spec invariants + 17 red-team & differential fuzz suites
npm run test:san                         # GCC C11 AddressSanitizer + UndefinedBehaviorSanitizer (100k fuzz cases)
npm run test:purejs                      # 100% pure-JS fallback parity check
node examples/reverse-proxy-sidecar.js   # 50 concurrent retries -> 1 upstream call demo
node examples/agent-mesh.js              # multi-agent delegation + live F.CANCEL streaming demo
```

---

## License

Code: MIT (`LICENSE`) · Specification: CC BY 4.0 (`LICENSE-spec`). SPDX: `CC-BY-4.0 OR MIT`.
