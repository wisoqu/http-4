# HTTP/4 (`http4` v0.2.0)

> **[🇷🇺 Читать на русском (README.ru.md)](README.ru.md)** · **[Integration Guide (Russian)](docs/INTEGRATION.md)** · **[Protocol Spec (Russian)](spec/http4.md)** · **[Security Model](SECURITY.md)**

[![CI & Sanitizers](https://github.com/wisoqu/http-4/actions/workflows/ci.yml/badge.svg)](https://github.com/wisoqu/http-4/actions/workflows/ci.yml)

> **Status — Experimental Draft & Research Prototype:** `http4` is an independent engineering prototype exploring agent-native semantics for HTTP. It is **not** an IETF standard or affiliated with the IETF HTTP Working Group, and its protocol mechanics have not undergone independent third-party cryptanalysis or formal model checking (Tamarin/ProVerif).

**An experimental agent-native, cost-aware semantic layer for HTTP** — with an optional **C11 Node-API accelerator** (and automatic pure-JS fallback), **zero runtime npm dependencies**, **complete TypeScript definitions**, and **1-command / 1-line integration** for existing HTTP/1.1, HTTP/2, Python/FastAPI, Go, Express, and WinterCG Edge apps.

**Transport architecture:** `http4` separates semantics from the transport carrier. Frame integers use RFC 9000 §16 QUIC varints so frames can map directly onto QUIC streams (and `src/h3-compat.js` maps them onto RFC 9114 §7.2.8 HTTP/3 extension frames `0x42..0x4d`). In this Node.js implementation, the shipped binary wire carrier (`src/wire.js`) runs multiplexed streams over **TLS 1.3 / TCP** (`ALPN: h4`), alongside HTTP/1.1 and HTTP/2 gateways (`src/gateway.js`). A native UDP/QUIC carrier is a planned future binding.

---

## Why This Exists (What Broke Between Humans and AI Agents)

HTTP/1.1–3 were designed around human browsing. Autonomous AI agents strain three assumptions:
1. **Retry storms burn GPU/API compute, not just bandwidth:** 50 agents retrying the same slow LLM or tool call can trigger 50 duplicate upstream runs.
2. **Sub-agent fan-out strains centralized auth:** an orchestrator spawning narrow sub-agents either over-shares a broad API key or makes an auth-service round trip per hop.
3. **Per-IP rate limits cause CGNAT collateral damage:** when honest cloud/NAT agents share egress IPs with an unauthenticated flood, per-IP token buckets drop **`94.0%`** of honest requests (`6.0%` served in `npm run attack`).

`http4` addresses all three at the edge or application layer — **without requiring a backend rewrite**:
- **Singleflight Coalescing + Cost Ceilings (`INTENT` / `COST` / `RESULT`):** identical in-flight requests (`GET` or `h4-dedup`) execute **once**; callers declare `costCeiling` & `deadlineMs`; mid-stream `F.CANCEL` aborts server generation (`~97 µs` median over loopback TLS 1.3, plus `0.5 RTT` over a network) and refunds unused budget.
- **Offline Macaroon-Style Capabilities (`CAP`):** 1 Ed25519 signature check per root grant (cached in memory), then offline `HMAC-SHA256-128` attenuation per sub-agent hop (`~2.0 µs` raw C11 HMAC; `~5.8 µs` full token parse + claims encode + HMAC). Each hop is verified to narrow `scope`, `caps`, `tenant`, and `expiresAt`; widening is rejected at verification under standard HMAC-SHA256 unforgeability assumptions.
- **Client-Cooperative Limits + Priced Effort (`RATE` / `h4-pass` / PoE):** honest SDK clients self-account via HMAC receipts and stop locally before exceeding quota; under overload, servers issue either single-use `h4-pass` tokens (`~5.8 µs` full verify + replay check; `~2.0 µs` raw HMAC) or `SHA-256` / 4 KiB `MemHard` Proof-of-Effort challenges (`~450 ns` / `~3.3 µs` C11 server verify).
  - *Note on `h4-pass` (`http4/overload-pass`, legacy alias `http4/privacy-pass`):* despite the legacy module filename, `h4-pass` is an **issuer-linkable single-use `HMAC-SHA256-192` overload token**, **not** IETF Privacy Pass (RFC 9576–9578 blind signatures / VOPRF). It saves client CPU/battery during overload when the issuer and verifier are the same trust domain, without providing cryptographic unlinkability.

---

## Integrate in 60 Seconds (4 Ways — Pick Yours)

### Installation & Native Addon Behavior

Requires **Node.js ≥ 20** (zero runtime npm dependencies):

```bash
npm install github:wisoqu/http-4
```

- **`postinstall` C11 build & pure-JS fallback:** on install, `scripts/build-native.js` attempts to compile `native/h4_core.c` + `native/h4_napi.c` using `cc`/`gcc`/`clang`. If no C toolchain is installed, installation **still succeeds** with a single-line notice and `http4` runs automatically on its bit-equivalent pure-JS implementation.
- **Skip compilation (CI / serverless / read-only containers):** set `H4_SKIP_NATIVE=1 npm install` to skip invoking the C compiler during install, or `H4_PURE_JS=1` at runtime to force the pure-JS path.

### Option A: Zero-Code Sidecar Proxy (Python FastAPI, vLLM, Ollama, Go, Rust — Any Language)
Run `http4` in front of any HTTP backend. Duplicate agent retries with `h4-dedup` coalesce into **1 upstream call**, and L7 floods hit Proof-of-Effort before reaching your app:

```bash
npx http4 proxy --upstream http://127.0.0.1:8000 --port 8080 --budget 200 --ttl-ms 5000
```

### Option B: 1 Line for Express / Fastify / Node `http`
Protects routes without consuming `req` body streams (`express.json()`, `multer`, GraphQL, tRPC keep working untouched):

```js
import express from 'express';
import { h4Shield } from 'http4/adapters';

const app = express();
app.use(h4Shield({ budget: 200, windowMs: 10_000 }));
app.use(express.json());
app.post('/v1/chat', (req, res) => res.json({ subject: req.h4.subject, ok: true }));
app.listen(3000);
```

### Option C: 1 Line for Next.js App Router / Cloudflare Workers / Bun / Deno / Hono
Wraps any WinterCG `(Request) => Promise<Response>` handler with singleflight coalescing, tenant-isolated caching, 0-RTT `425` protection, and PoE rate limiting:

```js
import { withH4 } from 'http4/adapters';

export default {
  fetch: withH4(async (req) => Response.json({ ok: true }), {
    budget: 200,
    defaultTtlMs: 5_000,
  }),
};
```

### Option D: Multi-Agent SDK (`fetch`-Compatible + Offline Delegation & Streaming)

```js
import { createH4Fetch, AgentSession, CAPS } from 'http4';

const h4Fetch = createH4Fetch({ maxEffortBits: 20 }); // upgrades via Alt-Svc when available
const orchestrator = new AgentSession({ token: rootGrant, h4Fetch, budget: 100 });

// Narrow a sub-agent capability offline (~5.8 µs full token attenuation, 0 auth-server calls):
const docReader = orchestrator.delegate({
  caps: CAPS.READ,
  scope: '/v1/docs',
  budget: 25,
  delegable: false,
});

const res = await docReader.fetch('https://api.example.com/v1/docs/spec');

// Live streaming with F.CANCEL server abort & unused budget refund:
const ac = new AbortController();
for await (const chunk of orchestrator.stream('h4://api.example.com:8443/v1/llm/stream', { signal: ac.signal })) {
  if (enoughContext(chunk)) ac.abort(); // sends F.CANCEL on the stream
}
```

---

## Reproducible Benchmarks

Measured on **2 vCPU Intel Xeon @ 2.60 GHz, 4 GB RAM, Linux x64, Node.js v22.22.3, GCC 12.2.0** (`C11 N-API` enabled; pure-JS fallback numbers noted where relevant). Reproduce on your hardware with `npm run bench` and `npm run attack`.

### 1. Micro & End-to-End Benchmarks (`npm run bench`)

| Metric | Measured Result (`C11 N-API`) | Notes / Pure-JS Comparison |
|---|---|---|
| Wire size (4 benchmark cases vs HTTP/1.1 text) | **12 B** (`simple GET`, `6.0×` vs `72 B`) · **48–55 B** (`3.0–4.2×` vs `157–200 B`) | HTTP/2–3 HPACK/QPACK is typically **30–60 B** on a cold dynamic table; H4 keeps **zero per-connection dynamic table state** (static table ID negotiated once via `HELLO.tableVersion`) |
| Full binary request parse (`79 B` flight) | **~693 ns** (`1.44 M ops/s`) | `~717 ns` in pure JS |
| Raw `HMAC-SHA256-128` primitive | **~1.95 µs** (`0.51 M ops/s`) | `~2.75 µs` in pure JS |
| Full 1-hop `attenuate()` / full `PassIssuer.redeem()` | **~5.79 µs** / **~5.77 µs** | Includes binary parse/encode or base64url + replay map (`~7.5 µs` / `~7.2 µs` pure JS) |
| Capability `verify()` (2 hops, cached root vs cold Ed25519) | **~13.7 µs** vs **~144.8 µs** | **11×** speedup from root-grant signature caching |
| End-to-end `H4Server` serve (sync path) vs reject | **~20.6 µs** (`~48.7k req/s`) vs **~8.6 µs** | Rejecting hostile traffic is **2.4×** cheaper than serving |
| `F.CANCEL` abort propagation (loopback TLS 1.3) | **~97 µs** median (`< 0.15 ms`) | Client `ac.abort()` → server route `AbortSignal` (`+ 0.5 RTT` on real WAN) |
| PoE solver rate (1 core, `SHA-256`) | **~2.55–2.97 M hashes/s** | vs **~0.52 M hashes/s** pure JS (**~5–6×** C11 speedup) |
| Defender PoE verify (`SHA-256` / `4 KiB MemHard`) | **~448 ns** / **~3.32 µs** | O(1) verification at any difficulty (`~1.97 µs` / `~9.81 µs` pure JS) |

### 2. Shared-CGNAT L7 Flood Simulation (`npm run attack`)

Default scenario (`bench/attack-sim.js`): **`40,000` requests** (`5,000` from **50 honest agents** attempting `100` reqs each; `35,000` from **500 unauthenticated attacker agents**) sharing **8 egress IPs** (**~69 agents / IP**). Per-agent quota is **`50` units/10s**; classical per-IP allowance is **`300` req/IP/10s** (`2,400` total across 8 IPs):

| Metric | Classical (per-IP) | Classical (per-API-key + anon IP) | HTTP/4 |
|---|---:|---:|---:|
| **Honest requests served** (of `5,000`) | `300` (**6.0%**) | `2,500` (**50.0%**) | `2,500` (**50.0%**) |
| **Honest unserved / over-quota** | `4,700` (**94.0%**) | `2,500` (**50.0%**) | `2,500` (**50.0%**) |
| ↳ *stopped client-side (never hit wire)* | `0` | `0` | **`2,500`** |
| **Attacker requests served** (of `35,000`) | `2,100` (**6.0%**) | `400` (**1.1%**) | `400` (**1.1%**) |
| **Attacker rejected w/ priced PoE effort** | `0` | `0` | **`34,600`** |
| **Simulated origin CPU time** | `~6 ms` *(bare counter)* | `~5 ms` *(bare counter)* | `~534 ms` *(~14.2 µs/wire req)* |

**Reading these numbers accurately:**
1. **Why `50.0%` honest served (`2,500 / 5,000`):** each of the 50 honest agents attempts 100 requests in a single 10s window against a 50-unit per-agent budget. Every honest agent receives **100% of its 50-unit quota** (`50 × 50 = 2,500`), and in HTTP/4 the remaining `2,500` over-budget attempts are self-blocked locally by `H4Client.shouldSend()` before touching the network (`0` server-side false rejections).
2. **Caller ID vs. HTTP/4 semantics:** a classical per-API-key limiter *also* reaches `50.0%` honest / `1.1%` attacker if every sub-agent already holds a distinct pre-provisioned API key. HTTP/4's specific additions are: deriving those 50 sub-agent tokens **offline from 1 root grant** (0 auth-DB lookups), suppressing over-budget traffic **client-side**, and replacing free `429` responses with **`34,600` priced-effort challenges**.
3. **Origin CPU row:** the two classical baselines in `attack-sim.js` are bare in-memory `Map` counters doing zero header/frame parsing or cryptography, whereas the HTTP/4 column runs full binary frame/header/capability/receipt processing (`~14.2 µs` per wire request).

---

## Verification & Sanitizer Suite

```bash
npx http4 doctor                         # check runtime & C11 N-API hash rate
npm test                                 # 62 spec invariants + 18 red-team & differential fuzz tests
npm run test:san                         # GCC C11 AddressSanitizer + UndefinedBehaviorSanitizer (100k fuzz cases)
npm run test:purejs                      # 62 + 18 tests under H4_PURE_JS=1 pure-JS fallback
npm run check:readme                     # verify README CGNAT numbers match live attack-sim output
node examples/reverse-proxy-sidecar.js   # 50 concurrent retries -> 1 upstream call demo
node examples/agent-mesh.js              # multi-agent delegation + live F.CANCEL streaming demo
```

---

## License

- **Published npm package (`src/`, `bin/`, `native/`, `types/`):** MIT (`LICENSE`).
- **Protocol specification (`spec/http4.md` in git repository):** CC BY 4.0 (`LICENSE-spec`).
