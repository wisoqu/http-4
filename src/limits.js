// ─────────────────────────────────────────────────────────────────────────────
// H4-LIMIT: rate limiting that the *client* helps enforce.
//
// Three tiers, each cheaper than the last:
//   1. COOPERATIVE (default, costs the server ~1 HMAC)
//   2. ENFORCED    (costs the server ~2 integer lookups: instance + aggregate)
//   3. EFFORT      (costs the server 1 SHA-256 + single-use nonce check)
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { CLASS } from './frames.js';

export const CLASS_WEIGHT = { [CLASS.CHEAP]: 1, [CLASS.NORMAL]: 5, [CLASS.EXPENSIVE]: 60 };

const b64u = (b) => b.toString('base64url');
const RECEIPT_RE = /^[0-9]+(\.[0-9a-z]+){4}$/;

function toUInt53(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(Number.MAX_SAFE_INTEGER, Math.floor(n));
}

// ── Receipt encoding: ver.window.spent.blockedUntilMs.nonce (base36, 53-bit safe)
export function encodeReceipt(r) {
  const ver = toUInt53(r.ver ?? 1);
  const window = toUInt53(r.window);
  const spent = toUInt53(r.spent);
  const blockedUntil = toUInt53(r.blockedUntil);
  const nonce = toUInt53(r.nonce);
  return `${ver}.${window.toString(36)}.${spent.toString(36)}.${blockedUntil.toString(36)}.${nonce.toString(36)}`;
}

export function decodeReceipt(s) {
  if (typeof s !== 'string' || s.length > 128 || !RECEIPT_RE.test(s)) return null;
  const p = s.split('.');
  if (p.length !== 5) return null;
  const ver = parseInt(p[0], 10);
  const window = parseInt(p[1], 36);
  const spent = parseInt(p[2], 36);
  const blockedUntil = parseInt(p[3], 36);
  const nonce = parseInt(p[4], 36);
  if (
    ver !== 1 ||
    !Number.isSafeInteger(window) ||
    !Number.isSafeInteger(spent) ||
    !Number.isSafeInteger(blockedUntil) ||
    !Number.isSafeInteger(nonce)
  ) {
    return null;
  }
  return { ver, window, spent, blockedUntil, nonce };
}

export function signReceipt(receipt, key) {
  return b64u(crypto.createHmac('sha256', key).update(receipt).digest().subarray(0, 12));
}

export function verifyReceipt(receiptStr, macStr, key) {
  if (typeof receiptStr !== 'string' || typeof macStr !== 'string' || !key) return null;
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
  if (bits <= 0) return true;
  if (bits > buf.length * 8) return false;
  let have = 0;
  for (const byte of buf) {
    if (byte === 0) { have += 8; if (have >= bits) return true; continue; }
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
    buf.writeUInt32BE(Math.floor(i / 0x100000000) >>> 0, 4);
    const h = crypto.createHash('sha256').update(buf).digest();
    if (hasLeadingZeroBits(h, bits)) return { nonce: i, hash: h };
  }
  return null;
}

export function checkPoE(challenge, nonce, bits) {
  if (!Number.isSafeInteger(nonce) || nonce < 0) return false;
  const buf = Buffer.alloc(8 + challenge.length);
  buf.writeUInt32BE(nonce >>> 0, 0);
  buf.writeUInt32BE(Math.floor(nonce / 0x100000000) >>> 0, 4);
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
    this.netMultiplier = netMultiplier;
    this.identityBonus = 2; // verified callers get 3× the anonymous allowance
    this.netEntries = new Map(); // address/grant → { window, spent }
    this.entries = new Map();    // subject → { window, spent, blockedUntil, lastNonce, punish }
    this.usedPoe = new Map();    // `${subject}:${poeWin}:${nonce}` → poeWin (anti-replay)
    this.stats = {
      receiptsOk: 0, receiptsMissing: 0, receiptsForged: 0,
      rejected: 0, poeServed: 0, poeRedeemed: 0, hmacOps: 0,
    };
  }

  _entry(subject, now) {
    const window = Math.floor(now / this.windowMs);
    let e = this.entries.get(subject);
    if (!e) {
      e = { window, spent: 0, blockedUntil: 0, lastNonce: -1, punish: 0 };
      if (this.entries.size >= 200000) this._gc(now);
      this.entries.set(subject, e);
    } else if (e.window !== window) {
      // Preserve lastNonce & punish across window rollovers so receipts from
      // older windows cannot be replayed in newer windows.
      e.window = window;
      e.spent = 0;
    }
    return e;
  }

  _gc(now) {
    const minWin = Math.floor(now / this.windowMs) - 1;
    for (const [k, v] of this.entries) {
      if (v.window < minWin) this.entries.delete(k);
    }
    if (this.entries.size >= 200000) {
      this.entries.delete(this.entries.keys().next().value);
    }
  }

  _gcNet(window) {
    for (const [k, v] of this.netEntries) {
      if (v.window < window - 1) this.netEntries.delete(k);
    }
    if (this.netEntries.size >= 50000) {
      this.netEntries.delete(this.netEntries.keys().next().value);
    }
  }

  /**
   * Single entry point, four cheap steps, no allocations on the hot path.
   * Returns {allow, code, retryAfterMs, difficulty, pressure, budgetRemaining, tier}.
   */
  check({
    subject, net = null, netAllowance = 0, costClass = CLASS.CHEAP,
    receipt = null, mac = null, sessionKey = null, identityTrusted = false,
  }, now = Date.now()) {
    const pressure = this.pressure();
    const weight = CLASS_WEIGHT[costClass] ?? 1;
    const e = this._entry(subject, now);
    const tier = [];
    const window = e.window;

    // Aggregate key: bounds instance churn for anonymous callers and token
    // fan-out for identified ones.
    if (net) {
      let n = this.netEntries.get(net);
      if (!n || n.window !== window) {
        n = { window, spent: 0 };
        if (this.netEntries.size >= 50000) this._gcNet(window);
        this.netEntries.set(net, n);
      }
      n.spent += weight;
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
      return { allow: false, code: 'RATE_LIMITED', retryAfterMs: e.blockedUntil - now, pressure, tier: ['blocked'] };
    }

    // Tier 1 — cooperative receipt.
    let cooperative = false;
    if (receipt && mac && sessionKey) {
      const r = verifyReceipt(receipt, mac, sessionKey);
      this.stats.hmacOps++;
      if (!r) {
        this.stats.receiptsForged++;
        e.punish = Math.min(e.punish + 1, 6);
      } else if (r.nonce <= e.lastNonce) {
        this.stats.receiptsForged++;
        e.punish = Math.min(e.punish + 1, 6); // replay / rollback
      } else {
        e.lastNonce = r.nonce;
        // Only merge reported spend when the receipt belongs to the current window
        // so boundary-straddling in-flight requests don't pollute the fresh window.
        if (r.window === window && r.spent > e.spent) e.spent = r.spent;
        if (r.blockedUntil > e.blockedUntil) e.blockedUntil = r.blockedUntil;
        cooperative = true;
        this.stats.receiptsOk++;
        tier.push('cooperative');
        // Honest client that blocked itself: honour it under load, relax when calm.
        if (r.blockedUntil > now) {
          if (pressure < 64) {
            e.blockedUntil = 0;
            tier.push('relaxed');
          } else {
            this.stats.rejected++;
            return { allow: false, code: 'RATE_LIMITED', retryAfterMs: e.blockedUntil - now, pressure, tier };
          }
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
      effectiveBudget: effective,
      blockUntilMs: pressure >= 128 ? now + 250 : 0, // tell the client to slow down early
      tier,
    };
  }

  /**
   * Verify and redeem a single-use Proof-of-Effort solution inline (no recursion).
   * Credits both the subject bucket and the aggregate net bucket, and prevents
   * nonce replay within the PoE challenge window.
   */
  redeemPoE({ subject, net = null, poeWindow, challenge, nonce, difficulty, costClass = CLASS.CHEAP }, now = Date.now()) {
    if (!Number.isSafeInteger(nonce) || nonce < 0) return null;
    const replayKey = `${subject}:${poeWindow}:${nonce}`;
    if (this.usedPoe.has(replayKey)) return null;
    if (!checkPoE(challenge, nonce, difficulty)) return null;

    if (this.usedPoe.size >= 50000) {
      for (const [k, w] of this.usedPoe) {
        if (w < poeWindow - 1) this.usedPoe.delete(k);
      }
      if (this.usedPoe.size >= 50000) this.usedPoe.delete(this.usedPoe.keys().next().value);
    }
    this.usedPoe.set(replayKey, poeWindow);

    const weight = CLASS_WEIGHT[costClass] ?? 1;
    const credit = weight * 4;
    const e = this._entry(subject, now);
    // Bring subject back within effective budget and grant headroom for this + 3 more requests
    const effective = this.budget * (1 + (this.identityBonus ?? 2));
    e.spent = Math.max(0, Math.min(e.spent, this.budget) - credit);
    e.blockedUntil = 0;

    if (net) {
      const n = this.netEntries.get(net);
      if (n) n.spent = Math.max(0, n.spent - credit);
    }
    this.stats.poeRedeemed++;
    return {
      allow: true, code: 'OK', pressure: this.pressure(),
      budgetRemaining: Math.max(0, this.budget - e.spent),
      effectiveBudget: effective,
      blockUntilMs: 0,
      tier: ['poe'],
    };
  }

  // Per-connection random session key.
  static sessionKey() { return crypto.randomBytes(32); }

  // Stateless cluster session key (spec §12.1): any edge node sharing `clusterSecret`
  // can issue and verify receipt MACs for `peerId` without sticky sessions.
  static deriveSessionKey(clusterSecret, peerId) {
    return crypto.createHmac('sha256', clusterSecret).update('h4-rl-v1|').update(String(peerId)).digest();
  }
}
