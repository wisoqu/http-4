# HTTP/4 Security Model, Hardening Invariants, & Boundary Assumptions

This document specifies the threat model, mitigated attack classes,
cryptographic domain separation, native C11 memory-safety verification, and
**explicitly isolated external deployment assumptions** for `http4` (`v0.2.0`).

> **Experimental Prototype Notice:** `http4` is an experimental protocol and reference implementation (not an IETF standard). While covered by 62 conformance invariants, 18 red-team/differential fuzz tests, and 100k C11 ASan+UBSan cases, it has not undergone independent third-party cryptographic audit or formal model checking (Tamarin/ProVerif).

---

## 1. Threat Model

`http4` assumes an adversarial network and untrusted clients/sub-agents:
- **Byzantine callers** may forge or replay `h4-rl` receipts, tamper with
  macaroon capability chains, attempt privilege/scope/tenant escalation, replay
  `h4-pass` tokens or PoE nonces, inject CRLF/NUL control bytes, send truncated
  or oversized binary frames, or flood streams over a single TLS connection.
- **Compromised leaf sub-agents** hold valid attenuated bearer tokens and may
  attempt to widen scope, re-enable delegation, switch tenants, or fan out into
  thousands of instances.
- **Untrusted / rogue origins** may demand astronomical Proof-of-Effort
  difficulty (`28+` bits) to trap an agent's CPU.

---

## 2. Eliminated Vulnerability Classes & Verified Defenses

| Layer | Threat / Attack Class | Defense & Code Location | Automated Verification |
|---|---|---|---|
| **Native C11 / N-API** | Buffer over-read, integer wrap, unaligned UB, timing leaks | Bounds-checked QUIC varints, volatile constant-time compare (`h4_ct_equal`), zero `#ifdef` divergence (`native/h4_core.c`, `native/h4_napi.c`) | `npm run test:san` (`gcc -fsanitize=address,undefined`, 100k heap-bounded fuzz cases) + 2,000 C↔JS differential vectors |
| **Cryptography** | Cross-protocol / cross-primitive signature & MAC confusion | Explicit domain tags on every Ed25519 signature, HMAC link, receipt, PoE challenge, MemHard phase, and pass token | `test/security-audit.js` §2 |
| **Capabilities** | Unsigned `maxSubs`, `verifyCache` forgery, non-delegable chain extension, tenant switching, `/v1/items-secret` sibling bypass, path traversal (`%2e`, `\0`, `\`) | Root Ed25519 covers `H4-CAP-ROOT-v1\0 ‖ ver ‖ keyId ‖ maxSubs ‖ claims0`; cache key binds `(pubFp, signedRoot, sig0)`; segment-aware `isSubScope`; O(1) `revokeGrant(id)` & `remove(keyId)` (`src/identity.js`) | `test/run.js` §5 + `test/security-audit.js` §2 |
| **Headers & Framing** | CRLF / NUL HTTP response splitting, pseudo-header smuggling, prototype route pollution (`toString`), truncated frame clamping | Strict `\r`/`\n`/`\0`/whitespace rejection, 32 KB header cap, `Object.create(null)` + `Object.hasOwn`, strict `iterFrames` (`src/headers.js`, `src/frames.js`, `src/server.js`) | `test/run.js` §4, §8 + `test/security-audit.js` §3 |
| **Overload & DDoS** | GPU/ASIC PoE asymmetry, mobile battery drain, PoE replay, dual-stack IPv6 (`::ffff:x.x.x.x`) quota doubling | 4 KB cache-hard `memhard` puzzle (`poeMode: 'memhard'`), single-use issuer-linkable `h4-pass` overload tokens (`src/privacy-pass.js` — HMAC-SHA256-192, *not* RFC 9576–9578 blind Privacy Pass), single-use `usedPoe` table, `normalizePeerIp` (`src/limits.js`, `src/server.js`) | `test/security-audit.js` §4, §5 |
| **0-RTT Early Data** | Replay of non-idempotent `MUTATE` requests or `h4-rl` receipts in TLS/QUIC 0-RTT | `earlyData` guard refuses mutations lacking `intent.idem` with `REJECT.DEFERRED` (`425 Too Early`) and skips receipt replay penalty (`src/server.js`, `src/gateway.js`) | `test/security-audit.js` §4 |
| **Cache & Coalescing** | Cross-tenant cache bleed, `BigInt+Buffer` size-estimation OOM bypass, 5xx negative cache poisoning | Authenticated `id:<tenant>` vs `anon:` cache namespace, O(1) binary buffer accounting in `H4Cache`, `< 500` auto-cache rule (`src/cache.js`, `src/server.js`) | `test/run.js` §7, §8 + `test/security-audit.js` §5 |
| **TLS Wire Transport** | ALPACA cross-protocol confusion, pre-`HELLO` Slowloris stall, Rapid-Reset stream flood | Mandatory `strictAlpn` (`h4`/`h4/1`), `handshakeTimeoutMs` (5s), `idleTimeoutMs` (60s), `maxConcurrentStreams` (256), `TCP_NODELAY` (`src/wire.js`) | `test/security-audit.js` §6 |
| **Client SDK** | Rogue server demanding `28`-bit PoE to freeze client CPU | `maxEffortBits` ceiling (default `20` in `createH4Fetch`, `22` in `H4Client`) immediately refuses excessive puzzles (`src/client.js`, `src/sdk.js`) | `test/security-audit.js` §4 |

---

## 3. Cryptographic Domain Separation Registry

Every cryptographic primitive in `http4` uses a distinct ASCII prefix so keys
or transcripts can never collide across subsystems:

| Subsystem | Primitive | Domain Prefix |
|---|---|---|
| Root Capability Grant | Ed25519 | `"H4-CAP-ROOT-v1\0"` |
| Capability Attenuation Link | HMAC-SHA256-128 | `"H4-CAP-LINK-v1|"` |
| Cooperative Rate Receipt | HMAC-SHA256-96 | `"H4-RL-RECEIPT-v1|"` |
| Stateless Cluster Session Key | HMAC-SHA256-256 | `"h4-rl-v1|"` |
| Proof-of-Effort Challenge | SHA-256 | `"H4-POE-CHAL-v1|"` |
| MemHard Scratchpad Seed / Finalize | SHA-256 | `"H4-MH1|"` / `"H4-MH2|"` |
| Single-Use Overload Pass (`h4-pass`, issuer-linkable; not RFC 9576–9578) | HMAC-SHA256-192 | `"H4-PASS-v1|"` |

---

## 4. Isolated External & Deployment Assumptions

The following security properties lie outside an application-layer library and
**MUST** be enforced by deployment infrastructure when running in production:

1. **Volumetric L3/L4 Packet Floods (UDP / TCP SYN Amplification)**
   - *Boundary*: `http4` prices L7 compute (`~20.6 µs` serve, `~8.6 µs` reject, `~448 ns` C11 PoE verify), not NIC ring-buffer packet floods.
   - *Operator Requirement*: Enable QUIC `RETRY` stateless address validation tokens on UDP ingress and run L3/L4 XDP/eBPF or Anycast DDoS scrubbing upstream.

2. **Cluster-Wide State Synchronization (Revocation, Replay, Idempotency)**
   - *Boundary*: `Limiter.deriveSessionKey(clusterSecret, peer)` makes cooperative receipt verification stateless across an edge fleet, whereas `KeyRegistry.revokedGrants`, `PassIssuer.redeemed`, `Limiter.usedPoe`, and `H4Server.idemStore` are bounded per-process `Map`/`Set` structures.
   - *Operator Requirement*: In multi-node edge deployments without consistent-hash routing per `grant`/`subject`, keep root grant TTLs short (`≤ 300 s`) and replicate grant revocations / `h4-pass` redemptions via a shared store (Redis / Raft) or sticky QUIC Connection-ID routing.

3. **Trusted Proxy & Peer IP Attribution**
   - *Boundary*: `src/wire.js` and `src/gateway.js` derive `peer` from the kernel socket `remoteAddress` (canonicalized via `normalizePeerIp`) and intentionally **ignore** untrusted `X-Forwarded-For` headers so callers cannot spoof arbitrary IPs.
   - *Operator Requirement*: When deploying behind a trusted reverse proxy or CDN (e.g., Cloudflare Workers via `toWebHandler`), pass the verified edge client IP explicitly via `env.remoteAddress` only after stripping client-supplied forwarding headers at the perimeter.

4. **Bearer Capability Token Confidentiality**
   - *Boundary*: Like OAuth2 tokens and Macaroons, an H4 capability token is a bearer credential for its narrowed scope until `expiresAt` or `revokeGrant()`.
   - *Operator Requirement*: Never transmit capability tokens over cleartext transports (`minVersion: 'TLSv1.3'` is enforced by `src/wire.js`), mint sub-agent leaf tokens with `delegable: 0`, and bind narrow `scope` + short `expiresAt`.

5. **Post-Quantum Root Signatures (Roadmap `TOKEN_VER = 2`)**
   - *Boundary*: `TOKEN_VER = 1` uses Ed25519 for root grants and 128-bit HMAC-SHA256 for delegation links (Grover-resistant symmetric links, classical elliptic-curve root).
   - *Future Extension*: `TOKEN_VER = 2` is reserved for hybrid `Ed25519 + ML-DSA-44` root grants once FIPS 204 primitives are universally exposed in standard Node.js `node:crypto` builds.

---

## 5. Running the Security Verification Suite

```bash
npm run test:san       # C11 AddressSanitizer + UndefinedBehaviorSanitizer + 100k fuzz cases
npm run test:security  # 18 red-team & differential C11<->JS fuzz suites
npm run test:purejs    # Full 62 + 18 conformance & security audit under pure-JS fallback
```
