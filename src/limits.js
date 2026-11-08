// ─────────────────────────────────────────────────────────────────────────────
// H4-LIMIT: rate limiting that the *client* helps enforce, accelerated by C11.
//
// Four tiers, each cheaper than the origin:
//   1. COOPERATIVE (default, costs the server ~1 HMAC via C11 fast-path)
//   2. ENFORCED    (costs the server ~2 integer lookups: instance + aggregate)
//   3. PASS        (single-use `h4-pass` cryptographic token: 0 client CPU burn)
//   4. EFFORT      (SHA-256 or 4 KB cache-hard `memhard` puzzle + anti-replay)
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { CLASS } from './frames.js';
import { nativeBinding } from './native.js';

export const CLASS_WEIGHT = { [CLASS.CHEAP]: 1, [CLASS.NORMAL]: 5, [CLASS.EXPENSIVE]: 60 };

const RECEIPT_DOMAIN = Buffer.from('H4-RL-RECEIPT-v1|');
const CHAL_DOMAIN = Buffer.from('H4-POE-CHAL-v1|');
const MH1_DOMAIN = Buffer.from('H4-MH1|');
const MH2_DOMAIN = Buffer.from('H4-MH2|');

const b64u = (b) => b.toString('base64url');
const RECEIPT_RE = /^[0-9]+(\.[0-9a-z]+){4}$/;

function toUInt53(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(Number.MAX_SAFE_INTEGER, Math.floor(n));
}

function writeNoncePair(buf, nonce) {
  buf.writeUInt32BE(nonce >>> 0, 0);
  buf.writeUInt32BE(Math.floor(nonce / 0x100000000) >>> 0, 4);
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
  if (nativeBinding) {
    const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
    return b64u(nativeBinding.hmacSha256(keyBuf, RECEIPT_DOMAIN, Buffer.from(receipt), 12));
  }
  return b64u(crypto.createHmac('sha256', key).update(RECEIPT_DOMAIN).update(receipt).digest().subarray(0, 12));
}

export function verifyReceipt(receiptStr, macStr, key) {
  if (typeof receiptStr !== 'string' || typeof macStr !== 'string' || !key) return null;
  const expect = Buffer.from(signReceipt(receiptStr, key));
  const got = Buffer.from(macStr);
  if (expect.length !== got.length || !crypto.timingSafeEqual(expect, got)) return null;
  return decodeReceipt(receiptStr);
}

// ── Proof-of-effort (SHA-256 + 4 KB cache-hard `memhard`) ───────────────────

export function poeChallenge(subject, window, mode = 'sha256') {
  return crypto.createHash('sha256')
    .update(CHAL_DOMAIN)
    .update(String(subject))
    .update('|')
    .update(String(window))
    .update('|')
    .update(mode)
    .digest();
}

export function hasLeadingZeroBits(buf, bits) {
  if (bits <= 0) return true;
  if (bits > buf.length * 8) return false;
  let have = 0;
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    if (byte === 0) {
      have += 8;
      if (have >= bits) return true;
      continue;
    }
    have += Math.clz32(byte) - 24;
    return have >= bits;
  }
  return have >= bits;
}

/** Pure-JS reference implementation of the 4 KB cache-hard puzzle (bit-exact with C11). */
export function memHardHashJs(challenge, nonce) {
  const nbuf = Buffer.allocUnsafe(8);
  writeNoncePair(nbuf, nonce);
  const seed0 = crypto.createHash('sha256')
    .update(MH1_DOMAIN)
    .update(nbuf)
    .update(challenge)
    .digest();

  const s = new Uint32Array(8);
  for (let i = 0; i < 8; i++) s[i] = seed0.readUInt32BE(i * 4);

  const pad = new Uint32Array(1024);
  let acc = (s[0] ^ 0x9e3779b9) >>> 0;
  for (let i = 0; i < 1024; i++) {
    const w = (s[i & 7] + i) >>> 0;
    const rot = ((w << 13) | (w >>> 19)) >>> 0;
    acc = (acc ^ rot) >>> 0;
    acc = (Math.imul(acc, 0x85ebca6b) + 0xc2b2ae35) >>> 0;
    pad[i] = (acc ^ (acc >>> 16)) >>> 0;
  }

  let st = (s[1] ^ pad[s[2] & 1023]) >>> 0;
  for (let r = 0; r < 64; r++) {
    const idx = st & 1023;
    const v = pad[idx];
    st = Math.imul((st ^ v ^ r) >>> 0, 0xcc9e2d51) >>> 0;
    st = Math.imul(((st << 15) | (st >>> 17)) >>> 0, 0x1b873593) >>> 0;
    const dst = (idx + (st >>> 22) + 1) & 1023;
    pad[dst] = (pad[dst] ^ st) >>> 0;
  }

  const mix = Buffer.allocUnsafe(32);
  for (let k = 0; k < 8; k++) {
    const f = (pad[((st + k * 127) >>> 0) & 1023] ^ st) >>> 0;
    mix.writeUInt32BE(f, k * 4);
  }

  return crypto.createHash('sha256')
    .update(MH2_DOMAIN)
    .update(nbuf)
    .update(challenge)
    .update(mix)
    .digest();
}

export function memHardHash(challenge, nonce) {
  const ch = Buffer.isBuffer(challenge) ? challenge : Buffer.from(challenge);
  if (nativeBinding) return nativeBinding.memHardHash(ch, nonce);
  return memHardHashJs(ch, nonce);
}

export function solveMemHard(challenge, bits, maxIter = 1 << 22) {
  const ch = Buffer.isBuffer(challenge) ? challenge : Buffer.from(challenge);
  if (bits <= 0) return { nonce: 0, hash: Buffer.alloc(32) };
  if (bits > 28 || maxIter <= 0) return null;
  if (nativeBinding) return nativeBinding.solveMemHard(ch, bits, maxIter);
  for (let i = 0; i < maxIter; i++) {
    const h = memHardHashJs(ch, i);
    if (hasLeadingZeroBits(h, bits)) return { nonce: i, hash: h };
  }
  return null;
}

export function checkMemHard(challenge, nonce, bits) {
  if (!Number.isSafeInteger(nonce) || nonce < 0) return false;
  if (bits <= 0) return true;
  if (bits > 64) return false;
  const ch = Buffer.isBuffer(challenge) ? challenge : Buffer.from(challenge);
  if (nativeBinding) return nativeBinding.checkMemHard(ch, nonce, bits);
  return hasLeadingZeroBits(memHardHashJs(ch, nonce), bits);
}

export function solvePoE(challenge, bits, maxIter = 1 << 26, mode = 'sha256') {
  if (mode === 'memhard') return solveMemHard(challenge, bits, maxIter);
  const ch = Buffer.isBuffer(challenge) ? challenge : Buffer.from(challenge);
  if (bits <= 0) return { nonce: 0, hash: Buffer.alloc(32) };
  if (bits > 30 || maxIter <= 0) return null;
  if (nativeBinding) return nativeBinding.solvePoE(ch, bits, maxIter);
  const buf = Buffer.alloc(8 + ch.length);
  ch.copy(buf, 8);
  for (let i = 0; i < maxIter; i++) {
    writeNoncePair(buf, i);
    const h = crypto.createHash('sha256').update(buf).digest();
    if (hasLeadingZeroBits(h, bits)) return { nonce: i, hash: h };
  }
  return null;
}

export function checkPoE(challenge, nonce, bits, mode = 'sha256') {
  if (mode === 'memhard') return checkMemHard(challenge, nonce, bits);
  if (!Number.isSafeInteger(nonce) || nonce < 0) return false;
  if (bits <= 0) return true;
  if (bits > 64) return false;
  const ch = Buffer.isBuffer(challenge) ? challenge : Buffer.from(challenge);
  if (nativeBinding) return nativeBinding.checkPoE(ch, nonce, bits);
  const buf = Buffer.alloc(8 + ch.length);
  writeNoncePair(buf, nonce);
  ch.copy(buf, 8);
  return hasLeadingZeroBits(crypto.createHash('sha256').update(buf).digest(), bits);
}

// ── Server-side limiter ─────────────────────────────────────────────────────

export class Limiter {
  /**
   * @param {object} o
   *  budget      units available at window start
   *  windowMs    refill period
   *  pressure    fn() → 0..255 current system pressure (queue depth, CPU, …)
   *  poeMode     'sha256' | 'memhard'
   *  passIssuer  optional PassIssuer instance for `h4-pass` zero-CPU bypass
   */
  constructor({
    budget = 200,
    windowMs = 10_000,
    pressure = () => 0,
    netMultiplier = 4,
    poeMode = 'sha256',
    passIssuer = null,
  } = {}) {
    this.budget = budget;
    this.windowMs = windowMs;
    this.pressure = pressure;
    this.netMultiplier = netMultiplier;
    this.poeMode = poeMode;
    this.passIssuer = passIssuer;
    this.identityBonus = 2; // verified callers get 3× the anonymous allowance
    this.netEntries = new Map(); // address/grant → { window, spent }
    this.entries = new Map();    // subject → { window, spent, blockedUntil, lastNonce, punish }
    this.usedPoe = new Map();    // `${subject}:${poeWin}:${nonce}` → poeWin (anti-replay)
    this.stats = {
      receiptsOk: 0, receiptsMissing: 0, receiptsForged: 0,
      rejected: 0, poeServed: 0, poeRedeemed: 0, passRedeemed: 0, hmacOps: 0,
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

  _scaleDifficulty(rawBits) {
    if (this.poeMode === 'memhard') {
      return Math.max(4, Math.min(20, rawBits - 4));
    }
    return Math.min(rawBits, 28);
  }

  /**
   * Single entry point, four cheap steps, no allocations on the hot path.
   */
  check({
    subject, net = null, netAllowance = 0, costClass = CLASS.CHEAP,
    receipt = null, mac = null, sessionKey = null, identityTrusted = false,
    earlyData = false,
  }, now = Date.now()) {
    const pressure = this.pressure();
    const weight = CLASS_WEIGHT[costClass] ?? 1;
    const e = this._entry(subject, now);
    const tier = [];
    const window = e.window;

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
          return {
            allow: false, code: 'EFFORT_REQUIRED',
            difficulty: this._scaleDifficulty(8 + (pressure >> 5)),
            poeMode: this.poeMode, retryAfterMs: 0, pressure, tier,
          };
        }
        this.stats.rejected++;
        return { allow: false, code: 'RATE_LIMITED', retryAfterMs: this.windowMs - (now % this.windowMs), pressure, tier };
      }
    }

    if (e.blockedUntil > now) {
      this.stats.rejected++;
      return { allow: false, code: 'RATE_LIMITED', retryAfterMs: e.blockedUntil - now, pressure, tier: ['blocked'] };
    }

    // Tier 1 — cooperative receipt (skip replay punishment on 0-RTT earlyData).
    let cooperative = false;
    if (receipt && mac && sessionKey && !earlyData) {
      const r = verifyReceipt(receipt, mac, sessionKey);
      this.stats.hmacOps++;
      if (!r) {
        this.stats.receiptsForged++;
        e.punish = Math.min(e.punish + 1, 6);
      } else if (r.nonce <= e.lastNonce) {
        this.stats.receiptsForged++;
        e.punish = Math.min(e.punish + 1, 6);
      } else {
        e.lastNonce = r.nonce;
        if (r.window === window && r.spent > e.spent) e.spent = r.spent;
        if (r.blockedUntil > e.blockedUntil) e.blockedUntil = r.blockedUntil;
        cooperative = true;
        this.stats.receiptsOk++;
        tier.push('cooperative');
        if (r.blockedUntil > now) {
          if (pressure < 64) {
            e.blockedUntil = 0;
            tier.push('relaxed');
          } else {
            this.stats.rejected++;
            return { allow: false, code: 'RATE_LIMITED', retryAfterMs: r.blockedUntil - now, pressure, tier };
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
      const punishScale = 1 + e.punish;
      const difficulty = this._scaleDifficulty(6 + 4 * punishScale + (pressure >> 5));
      if (pressure >= 128 || e.punish > 0) {
        this.stats.poeServed++;
        tier.push('effort');
        return { allow: false, code: 'EFFORT_REQUIRED', difficulty, poeMode: this.poeMode, retryAfterMs: 0, pressure, tier };
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
      blockUntilMs: pressure >= 128 ? now + 250 : 0,
      tier,
    };
  }

  /**
   * Redeem a single-use cryptographic `h4-pass` token in ~2 µs (0 client CPU burn).
   */
  redeemPass({ subject, net = null, passToken, costClass = CLASS.CHEAP }, now = Date.now()) {
    if (!this.passIssuer || !passToken) return null;
    const res = this.passIssuer.redeem(passToken, { now });
    if (!res.ok) return null;

    const weight = CLASS_WEIGHT[costClass] ?? 1;
    const credit = weight * 4;
    const e = this._entry(subject, now);
    const effective = this.budget * (1 + (this.identityBonus ?? 2));
    e.spent = Math.max(0, Math.min(e.spent, this.budget) - credit);
    e.blockedUntil = 0;

    if (net) {
      const n = this.netEntries.get(net);
      if (n) n.spent = Math.max(0, n.spent - credit);
    }
    this.stats.passRedeemed++;
    return {
      allow: true, code: 'OK', pressure: this.pressure(),
      budgetRemaining: Math.max(0, this.budget - e.spent),
      effectiveBudget: effective,
      blockUntilMs: 0,
      tier: ['pass'],
    };
  }

  /**
   * Verify and redeem a single-use Proof-of-Effort solution inline (no recursion).
   */
  redeemPoE({ subject, net = null, poeWindow, challenge, nonce, difficulty, costClass = CLASS.CHEAP, mode = this.poeMode }, now = Date.now()) {
    if (!Number.isSafeInteger(nonce) || nonce < 0) return null;
    const replayKey = `${subject}:${poeWindow}:${nonce}`;
    if (this.usedPoe.has(replayKey)) return null;
    if (!checkPoE(challenge, nonce, difficulty, mode)) return null;

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

  /** Refund unused reserved budget (e.g. when an agent cancels a stream early via F.CANCEL). */
  refund({ subject, net = null, units = 0 }, now = Date.now()) {
    if (!Number.isFinite(units) || units <= 0) return;
    const e = this._entry(subject, now);
    e.spent = Math.max(0, e.spent - units);
    if (net) {
      const n = this.netEntries.get(net);
      if (n) n.spent = Math.max(0, n.spent - units);
    }
  }

  static sessionKey() { return crypto.randomBytes(32); }

  static deriveSessionKey(clusterSecret, peerId) {
    return crypto.createHmac('sha256', clusterSecret).update('h4-rl-v1|').update(String(peerId)).digest();
  }
}
