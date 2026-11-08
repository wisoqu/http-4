// ─────────────────────────────────────────────────────────────────────────────
// H4 cache: budget-aware, memoising, and *coalescing*.
//
// Three things agents changed about caching:
//   1. The expensive part is often not bytes, it is *inference*. Two agents
//      asking semantically identical things should share one model call.
//   2. Agents retry. Aggressively. Deduplicating in-flight identical work is
//      worth more than any byte cache.
//   3. Load is bursty, so a cache must be able to say "not now, ask me in 2s"
//      instead of doing expensive work it will have to throw away.
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { CACHE } from './frames.js';

export const hashKey = (...parts) =>
  crypto.createHash('sha256').update(parts.join('\u0000')).digest('base64url').slice(0, 22);

export class H4Cache {
  constructor({ maxBytes = 64 * 1024 * 1024, defaultTtlMs = 30_000, pressure = () => 0 } = {}) {
    this.map = new Map();
    this.maxBytes = maxBytes;
    this.bytes = 0;
    this.defaultTtlMs = defaultTtlMs;
    this.pressure = pressure;
    this.inflight = new Map(); // dedup: key → Promise
    this.stats = { hits: 0, misses: 0, coalesced: 0, evictions: 0, stored: 0, savedComputeMs: 0 };
  }

  key(parts) { return hashKey(...parts); }

  get(k, now = Date.now()) {
    const e = this.map.get(k);
    if (!e) { this.stats.misses++; return null; }
    if (e.expiresAt < now) {
      // stale-while-revalidate: serve stale under pressure instead of recomputing
      if (this.pressure() >= 96 && e.value !== undefined) {
        this.stats.hits++; return { ...e, stale: true };
      }
      this.map.delete(k); this.bytes -= e.size; this.stats.misses++; return null;
    }
    // LRU touch
    this.map.delete(k); this.map.set(k, e);
    this.stats.hits++; return e;
  }

  set(k, value, { ttlMs = this.defaultTtlMs, computeMs = 0, memo = false, tags = [] } = {}) {
    const size = Buffer.byteLength(JSON.stringify(value) ?? '') + 64;
    const e = { value, expiresAt: Date.now() + ttlMs, size, computeMs, memo, tags, hits: 0 };
    const old = this.map.get(k);
    if (old) this.bytes -= old.size;
    this.map.set(k, e); this.bytes += size; this.stats.stored++;
    if (computeMs) this.stats.savedComputeMs += 0; // counted on hit instead
    while (this.bytes > this.maxBytes && this.map.size > 1) {
      const [oldK, oldE] = this.map.entries().next().value;
      this.map.delete(oldK); this.bytes -= oldE.size; this.stats.evictions++;
    }
    return e;
  }

  /**
   * Request coalescing — the single highest-leverage DoS defence for agent
   * traffic. N identical in-flight expensive requests cost the origin ONE
   * computation. During a retry storm this turns O(N) into O(1).
   */
  async coalesce(k, fn) {
    const existing = this.inflight.get(k);
    if (existing) { this.stats.coalesced++; return { value: await existing, coalesced: true }; }
    const p = (async () => fn())();
    this.inflight.set(k, p);
    try { return { value: await p, coalesced: false }; }
    finally { this.inflight.delete(k); }
  }

  sizeInfo() { return { entries: this.map.size, bytes: this.bytes, ...this.stats }; }
}
