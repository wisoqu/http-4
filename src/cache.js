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

export function hashKey(...parts) {
  const h = crypto.createHash('sha256');
  for (let i = 0; i < parts.length; i++) {
    const s = String(parts[i] ?? '');
    h.update(`${s.length}:`).update(s).update('|');
  }
  return h.digest('base64url').slice(0, 22);
}

function estimateSize(value) {
  if (Buffer.isBuffer(value)) return value.length + 64;
  if (typeof value === 'string') return Buffer.byteLength(value) + 64;
  try {
    return Buffer.byteLength(JSON.stringify(value) ?? '') + 64;
  } catch {
    return 256;
  }
}

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
        e.hits++;
        this.stats.hits++;
        this.stats.savedComputeMs += e.computeMs ?? 0;
        return { ...e, stale: true };
      }
      this.map.delete(k);
      this.bytes -= e.size;
      this.stats.misses++;
      return null;
    }
    // LRU touch
    this.map.delete(k);
    this.map.set(k, e);
    e.hits++;
    this.stats.hits++;
    this.stats.savedComputeMs += e.computeMs ?? 0;
    return e;
  }

  set(k, value, { ttlMs = this.defaultTtlMs, computeMs = 0, memo = false, tags = [], now = Date.now() } = {}) {
    const old = this.map.get(k);
    if (old) {
      this.map.delete(k);
      this.bytes -= old.size;
    }
    if (ttlMs <= 0) return null;
    const size = estimateSize(value);
    if (size > this.maxBytes) return null;

    const e = { value, expiresAt: now + ttlMs, size, computeMs, memo, tags, hits: 0 };
    this.map.set(k, e);
    this.bytes += size;
    this.stats.stored++;

    while (this.bytes > this.maxBytes && this.map.size > 0) {
      const [oldK, oldE] = this.map.entries().next().value;
      this.map.delete(oldK);
      this.bytes -= oldE.size;
      this.stats.evictions++;
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
