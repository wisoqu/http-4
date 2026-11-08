// ─────────────────────────────────────────────────────────────────────────────
// H4-LIMIT: rate limiting that the *client* helps enforce.
//
// The problem with every classical limiter: the server pays first. To reject a
// bot it must accept a connection, parse a request, hit a counter, build a
// response. That is the entire volume of a volumetric L7 attack.
//
// H4 flips it — three tiers, each cheaper than the last:
//
//   1. COOPERATIVE (default, costs the server ~1 HMAC)
//      After the handshake the server hands the client a per-session key. The
//      client sends `h4-rl: <receipt>,<mac>` on every request, where the receipt
//      is its own honest accounting: how many cost-units it has spent in this
//      window and until when it has blocked *itself*. The client does the
//      bookkeeping, the server does one HMAC (274k ops/s → ~3.6 µs) and a
//      monotonic-counter replay check.
//      A well-behaved client that hits its budget stops sending. The attack
//      never reaches the CPU: it is cancelled client-side, by the client's own
//      limiter, before the bytes exist.
//
//   2. ENFORCED (costs the server one integer)
//      Two keys, not one. A per-instance bucket alone is worthless because a
//      client can mint instance IDs for free; a per-address bucket alone is
//      unfair because it punishes everyone behind a CGNAT. So H4 enforces BOTH:
//      the instance bucket bounds a single agent, and a deliberately generous
//      aggregate bucket per network address bounds *instance churn*. A caller
//      with a verified capability token escapes the shared pool entirely — that
//      is the incentive to have an identity, and the reason honest clients do
//      not suffer when their neighbours misbehave.
//      Missing/stale/forged receipt → server falls back to a per-subject token
//      bucket. No HMAC, no allocation: ~1 dict lookup and an integer.
//
//   3. EFFORT (costs the server one SHA-256)
//      Under pressure, the server does not ban — it prices. A client that
//      cannot earn budget with identity can earn it with proof-of-effort.
//      Server cost stays constant while attacker cost grows as 2^difficulty.
//
// The point of tier 1 is not trust: it is that *honest clients see the ceiling
// earlier than the server does*. Collateral damage drops because the network
// degrades in proportion to a client's own reported spend rather than by
// hard-cutting everyone in a shared IP/CIDR bucket.
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { CLASS } from './frames.js';

// What each request class costs, in budget units. Operators tune these; the
// defaults encode "a cache hit is basically free, an LLM call is not".
export const CLASS_WEIGHT = { [CLASS.CHEAP]: 1, [CLASS.NORMAL]: 5, [CLASS.EXPENSIVE]: 60 };

const b64u = (b) => b.toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');

// ── Receipt encoding: fixed layout, ~46 bytes on the wire ───────────────────
//  ver.window.spent.blockedUntil.nonce
export function encodeReceipt(r) {
  // base36 keeps it short and parseable by eye in logs
  return `${r.ver ?? 1}.${(r.window | 0).toString(36)}.${(r.spent | 0).toString(36)}.${(r.blockedUntil | 0).toString(36)}.${(r.nonce | 0).toString(36)}`;
}

export function decodeReceipt(s) {
  const p = s.split('.');
  if (p.length !== 5) return null;
  return {
    ver: parseInt(p[0], 10),
    window: parseInt(p[1], 36), spent: parseInt(p[2], 36),
    blockedUntil: parseInt(p[3], 36), nonce: parseInt(p[4], 36),
  };
}

export function signReceipt(receipt, key) {
  return b64u(crypto.createHmac('sha256', key).update(receipt).digest().subarray(0, 12));
}

export function verifyReceipt(receiptStr, macStr, key) {
  const expect = Buffer.from(signReceipt(receiptStr, key));
  const got = Buffer.from(macStr);
  if (expect.length !== got.length || !crypto.timingSafeEqual(expect, got)) return null;
  return decodeReceipt(receiptStr);
}

// ── Proof-of-effort ─────────────────────────────────────────────────────────
// Challenge is derived, not stored: server recomputes it from (subject, window)
// so a fleet of edges shares challenges with zero state.

export function poeChallenge(subject, window) {
  return crypto.createHash('sha256').update(subject).update('|').update(String(window)).digest();
}

export function hasLeadingZeroBits(buf, bits) {
  let have = 0;
  for (const byte of buf) {
    if (byte === 0) { have += 8; if (have >= bits) return true; continue; }
    // count leading zeros of this byte
    let b = byte, z = 0;
    while ((b & 0x80) === 0) { z++; b = (b << 1) & 0xff; }
    have += z;
    return have >= bits;
  }
  return have >= bits;
}

export function solvePoE(challenge, bits, maxIter = 1 << 26) {
  const buf = Buffer.alloc(8 + challenge.length);
  challenge.copy(buf, 8);
  for (let i = 0; i < maxIter; i++) {
    buf.writeUInt32BE(i >>> 0, 0);
    const h = crypto.createHash('sha256').update(buf).digest();
    if (hasLeadingZeroBits(h, bits)) return { nonce: i, hash: h };
  }
  return null;
}

export function checkPoE(challenge, nonce, bits) {
  const buf = Buffer.alloc(8 + challenge.length);
  buf.writeUInt32BE(nonce >>> 0, 0);
  challenge.copy(buf, 8);
  return hasLeadingZeroBits(crypto.createHash('sha256').update(buf).digest(), bits);
}

// ── Server-side limiter ─────────────────────────────────────────────────────

export class Limiter {
  /**
   * @param {object} o
   *  budget      units available at window start
   *  windowMs    refill period
   *  pressure    fn() → 0..255 current system pressure (queue depth, CPU, …)
   */
  constructor({ budget = 200, windowMs = 10_000, pressure = () => 0, netMultiplier = 4 } = {}) {
    this.budget = budget;
    this.windowMs = windowMs;
    this.pressure = pressure;
    // Aggregate per-network allowance, in multiples of a single instance's
    // budget. High enough that a normal shared NAT is never throttled, low
    // enough that "spin up 10k identities from one address" gains nothing.
    this.netMultiplier = netMultiplier;
    this.identityBonus = 2; // verified callers get 3× the anonymous allowance
    this.netEntries = new Map(); // address → { window, spent }
    this.entries = new Map(); // subject → { window, spent, blockedUntil, lastNonce, punish }
    this.stats = { receiptsOk: 0, receiptsMissing: 0, receiptsForged: 0, rejected: 0, poeServed: 0, hmacOps: 0 };
  }

  _entry(subject, now) {
    const window = Math.floor(now / this.windowMs);
    let e = this.entries.get(subject);
    if (!e || e.window !== window) {
      e = { window, spent: 0, blockedUntil: 0, lastNonce: -1, punish: e ? e.punish : 0 };
      this.entries.set(subject, e);
      if (this.entries.size > 200000) this._gc(now);
    }
    return e;
  }

  _gc(now) {
    for (const [k, v] of this.entries) {
      if (v.window < Math.floor(now / this.windowMs) - 1) this.entries.delete(k);
    }
  }

  /**
   * Single entry point, four cheap steps, no allocations on the hot path.
   * Returns {allow, code, retryAfterMs, difficulty, pressure}.
   */
  check({ subject, net = null, netAllowance = 0, costClass = CLASS.CHEAP, receipt = null, mac = null, sessionKey = null, identityTrusted = false }, now = Date.now()) {
    const pressure = this.pressure();
    const weight = CLASS_WEIGHT[costClass] ?? 1;
    const e = this._entry(subject, now);
    const tier = [];

    // Aggregate key: bounds instance churn for anonymous callers and token
    // fan-out for identified ones. One integer, no allocation.
    if (net) {
      const window = Math.floor(now / this.windowMs);
      let n = this.netEntries.get(net);
      if (!n || n.window !== window) {
        n = { window, spent: 0 };
        this.netEntries.set(net, n);
        if (this.netEntries.size > 50000) this.netEntries.clear();
      }
      n.spent += weight;
      // For identified callers the aggregate allowance is scaled by maxSubs,
      // which the ISSUER signed — so an operator with 1000 agents legitimately
      // gets 1000 shares, while a stolen single-instance token still cannot be
      // fanned out into a fleet.
      const allowance = netAllowance || this.budget * this.netMultiplier * (identityTrusted ? 1 + this.identityBonus : 1);
      if (n.spent > allowance) {
        tier.push('net');
        if (pressure >= 96) {
          this.stats.poeServed++;
          return { allow: false, code: 'EFFORT_REQUIRED', difficulty: Math.min(8 + (pressure >> 5), 28), retryAfterMs: 0, pressure, tier };
        }
        this.stats.rejected++;
        return { allow: false, code: 'RATE_LIMITED', retryAfterMs: this.windowMs - (now % this.windowMs), pressure, tier };
      }
    }

    // A blocked subject is rejected for free.
    if (e.blockedUntil > now) {
      this.stats.rejected++;
      return { allow: false, code: 'RATE_LIMITED', retryAfterMs: e.blockedUntil - now, pressure, tier: 'blocked' };
    }

    // Tier 1 — cooperative receipt.
    let cooperative = false;
    if (receipt && mac && sessionKey) {
      const r = verifyReceipt(receipt, mac, sessionKey);
      this.stats.hmacOps++;
      if (!r) { this.stats.receiptsForged++; e.punish = Math.min(e.punish + 1, 6); }
      else if (r.nonce <= e.lastNonce) { this.stats.receiptsForged++; e.punish = Math.min(e.punish + 1, 6); } // replay / rollback
      else {
        e.lastNonce = r.nonce;
        // The client's own accounting is authoritative *if it is worse* than ours.
        if (r.spent > e.spent) e.spent = r.spent;
        if (r.blockedUntil > e.blockedUntil) e.blockedUntil = r.blockedUntil;
        cooperative = true;
        this.stats.receiptsOk++;
        tier.push('cooperative');
        // Honest client that blocked itself: honour it, but give it free money
        // when the server is calm. Self-limits should not be sticky.
        if (r.blockedUntil > now && pressure < 64) {
          e.blockedUntil = 0;
          tier.push('relaxed');
        }
      }
    } else {
      this.stats.receiptsMissing++;
    }
    if (!cooperative) tier.push('enforced');

    // Tier 2 — server-side bucket (authoritative spend).
    e.spent += weight;
    const trustedBonus = identityTrusted ? this.budget * (this.identityBonus ?? 2) : 0;
    const effective = this.budget + trustedBonus;

    if (e.spent > effective) {
      // Tier 3 — price the request instead of banning the caller.
      const punishScale = 1 + e.punish;
      const difficulty = Math.min(6 + 4 * punishScale + (pressure >> 5), 28);
      if (pressure >= 128 || e.punish > 0) {
        this.stats.poeServed++;
        tier.push('effort');
        return { allow: false, code: 'EFFORT_REQUIRED', difficulty, retryAfterMs: 0, pressure, tier };
      }
      e.blockedUntil = now + Math.min(this.windowMs * punishScale, 60_000);
      this.stats.rejected++;
      return {
        allow: false, code: 'RATE_LIMITED', retryAfterMs: e.blockedUntil - now, pressure,
        budgetRemaining: 0, tier,
      };
    }

    return {
      allow: true, code: 'OK', pressure,
      budgetRemaining: effective - e.spent,
      blockUntilMs: pressure >= 128 ? now + 250 : 0, // tell the client to slow down early
      tier,
    };
  }

  // Server hands this to the client in the handshake so receipts can't be forged.
  static sessionKey() { return crypto.randomBytes(32); }
}
