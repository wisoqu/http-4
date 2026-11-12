// ─────────────────────────────────────────────────────────────────────────────
// H4 Single-Use Overload Bypass Passes (`h4-pass` header)
//
// Solves the mobile/battery asymmetry of Proof-of-Effort: legitimate clients can
// acquire a wallet of compact, domain-separated, single-use passes during calm
// periods or authentication, and redeem 1 pass in ~2 µs during server overload
// without burning any client CPU cycles on SHA-256 / MemHard puzzles.
//
// Wire format (raw bytes, base64url-encoded in `h4-pass` header):
//   ver(1B = 1) ‖ keyId(varint) ‖ passId(16B) ‖ expiresAtSec(varint) ‖
//   HMAC192(secret, "H4-PASS-v1|" ‖ body)   [total ~43 raw bytes / 58 b64url chars]
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { Writer, Reader } from './varint.js';
import { nativeBinding } from './native.js';

export const PASS_VER = 1;
const PASS_ID_LEN = 16;
const PASS_MAC_LEN = 24; // 192-bit security margin
const PASS_DOMAIN = Buffer.from('H4-PASS-v1|');

function computePassMac(secret, body) {
  if (nativeBinding) {
    return nativeBinding.hmacSha256(secret, PASS_DOMAIN, body, PASS_MAC_LEN);
  }
  return crypto.createHmac('sha256', secret)
    .update(PASS_DOMAIN)
    .update(body)
    .digest()
    .subarray(0, PASS_MAC_LEN);
}

export class PassIssuer {
  constructor({
    secret = crypto.randomBytes(32),
    keyId = 1,
    ttlSec = 3600,
    maxRedeemed = 100_000,
    clock = () => Date.now(),
  } = {}) {
    this.secret = Buffer.isBuffer(secret) ? secret : Buffer.from(secret);
    this.keyId = keyId;
    this.ttlSec = ttlSec;
    this.maxRedeemed = maxRedeemed;
    this.clock = clock;
    // passIdHex -> expiresAtMs (single-use double-spend table, pruned lazily)
    this.redeemed = new Map();
  }

  /** Mint a single-use base64url pass token. */
  mint({ ttlSec = this.ttlSec, now = this.clock() } = {}) {
    const passId = crypto.randomBytes(PASS_ID_LEN);
    const expiresAtSec = Math.floor(now / 1000) + ttlSec;
    const w = new Writer(32);
    w.u8(PASS_VER).varint(this.keyId).raw(passId).varint(expiresAtSec);
    const body = w.finish();
    const mac = computePassMac(this.secret, body);
    return Buffer.concat([body, mac]).toString('base64url');
  }

  /** Mint a batch wallet of N independent single-use passes. */
  mintWallet(count = 8, opts = {}) {
    const out = [];
    for (let i = 0; i < count; i++) out.push(this.mint(opts));
    return out;
  }

  /** Verify and atomically spend a single-use pass token. */
  redeem(b64, { now = this.clock() } = {}) {
    if (typeof b64 !== 'string' || b64.length < 32 || b64.length > 256) {
      return { ok: false, why: 'malformed-pass' };
    }
    let raw;
    try {
      raw = Buffer.from(b64, 'base64url');
      if (raw.length < 1 + 1 + PASS_ID_LEN + 1 + PASS_MAC_LEN) {
        return { ok: false, why: 'short-pass' };
      }
      const body = raw.subarray(0, raw.length - PASS_MAC_LEN);
      const mac = raw.subarray(raw.length - PASS_MAC_LEN);
      const r = new Reader(body);
      const ver = r.u8();
      if (ver !== PASS_VER) return { ok: false, why: 'bad-pass-version' };
      const keyId = r.varint();
      if (keyId !== this.keyId) return { ok: false, why: 'unknown-pass-key' };
      const passId = r.slice(PASS_ID_LEN);
      const expiresAtSec = r.varint();
      if (!r.done) return { ok: false, why: 'trailing-pass-bytes' };

      const expected = computePassMac(this.secret, body);
      if (!crypto.timingSafeEqual(expected, mac)) {
        return { ok: false, why: 'bad-pass-mac' };
      }
      if (expiresAtSec * 1000 < now) {
        return { ok: false, why: 'expired-pass' };
      }

      const idHex = Buffer.from(passId).toString('hex');
      if (this.redeemed.has(idHex)) {
        return { ok: false, why: 'replayed-pass' };
      }
      // Single-use must mean single-use. The double-spend table is the only
      // record that a pass was already spent, so it must never drop an entry
      // whose TTL is still live — otherwise a spent (but unexpired) pass becomes
      // replayable again. Sweep expired entries, then fail closed if still full.
      if (this.redeemed.size >= this.maxRedeemed) {
        this.#pruneExpired(now, true);
        if (this.redeemed.size >= this.maxRedeemed) {
          return { ok: false, why: 'pass-table-full' };
        }
      }
      this.redeemed.set(idHex, expiresAtSec * 1000);
      this.#pruneExpired(now);
      return { ok: true, passId: idHex, expiresAt: expiresAtSec };
    } catch {
      return { ok: false, why: 'corrupt-pass' };
    }
  }

  /**
   * Lazily drop entries whose TTL has elapsed.
   *
   * The incremental pass (`full !== true`) only inspects a small batch so the hot
   * path stays O(1). `full` performs a complete sweep and is used before we would
   * otherwise be forced to evict a still-live entry.
   */
  #pruneExpired(now, full = false) {
    if (this.redeemed.size < 4096 && !full) return;
    const limit = full ? this.redeemed.size : 64;
    let checked = 0;
    for (const [k, expMs] of this.redeemed) {
      if (expMs < now) this.redeemed.delete(k);
      if (++checked >= limit) break;
    }
  }
}
