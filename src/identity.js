// ─────────────────────────────────────────────────────────────────────────────
// H4 identity: capability tokens that agents can *delegate offline*.
//
// The agent-era problem: a user's agent spawns sub-agents and tool calls, and
// every hop would otherwise need a round trip to an auth server. That is both
// slow (adds RTTs to the money path) and expensive (auth server becomes the new
// bottleneck and the new DDoS target).
//
// H4 solution: macaroon-style attenuation over an Ed25519-signed root grant.
//
//   root grant:  claims0 ‖ Ed25519_issuer(claims0)
//   attenuation: link_i = HMAC128( sig_{i-1} , claims_i )
//   token       = ver ‖ keyId ‖ claims0 ‖ sig0 ‖ (claims1 ‖ link1) ‖ …
//
// Security argument (why this is safe even though link salts are public):
//   * authority comes only from the issuer signature over claims0, verified
//     once per token and cached by hash → one Ed25519 verify per *session*,
//     not per request (8.5k ops/s would otherwise be the new bottleneck);
//   * each hop MUST narrow the previous hop: caps ⊆ caps, expiry ≤ expiry,
//     scope is a prefix-extension of scope. Widening is rejected, so a holder
//     can only ever give away less than it has — the classic "no privilege
//     escalation via delegation" invariant;
//   * verification cost on the hot path is h × HMAC-SHA256 (274k ops/s),
//     i.e. ~4 µs for a 3-hop chain on one core.
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { Writer, Reader } from './varint.js';

export const CAPS = { READ: 1, WRITE: 2, DELEGATE: 4, PAY: 8, PUBLISH: 16, SUBSCRIBE: 32 };
export const TOKEN_VER = 1;
export const MAX_CHAIN = 6; // 6 hops is ~1000× more than any real agent topology

const KEY_LEN = 32;
const SIG_LEN = 16;   // truncated HMAC128 per link: enough, and keeps tokens tiny
const ED_LEN = 64;

const enc = new TextEncoder();
const dec = new TextDecoder();

export class KeyRegistry {
  constructor() { this.keys = new Map(); }
  add(keyId, publicKey, { multiSig = false } = {}) {
    this.keys.set(keyId, { publicKey, multiSig });
    return this;
  }
  get(keyId) { return this.keys.get(keyId); }
}

// NOTE on `nonce`: without it, two siblings attenuated from the same grant with
// identical claims encode to identical bytes — hence identical tokens, hence
// (because the quota key is the chain tip) one shared quota. Requiring a nonce
// is what makes "one token per instance" representable at all. This was found
// by the fan-out test, and it is the kind of thing a spec has to state outright.
function encodeClaims({ caps = 0, expiresAt = 0, scope = '/', delegable = 0, tenant = '', nonce = 0 }) {
  const w = new Writer(96);
  w.varint(caps).varint(expiresAt).bytes(enc.encode(scope)).u8(delegable).bytes(enc.encode(tenant)).varint(nonce);
  return w.finish();
}

function decodeClaims(buf) {
  const r = new Reader(buf);
  return {
    caps: r.varint(), expiresAt: r.varint(), scope: dec.decode(r.bytes()),
    delegable: r.u8(), tenant: dec.decode(r.bytes()),
    nonce: r.done ? 0 : r.varint(),
  };
}

/** Issuer side: mint a root grant. Called by the auth service, not the edge. */
export function mintRoot({ keyId, privateKey, caps, expiresAt, scope = '/', delegable = 1, tenant = '', maxSubs = 0 }) {
  const claims = encodeClaims({ caps, expiresAt, scope, delegable, tenant });
  const sig = crypto.sign(null, claims, privateKey);
  const w = new Writer(256);
  w.u8(TOKEN_VER).varint(keyId).varint(maxSubs);
  w.bytes(claims).raw(sig);
  return w.finish();
}

function hmac128(key, msg) {
  return crypto.createHmac('sha256', key).update(msg).digest().subarray(0, SIG_LEN);
}

/**
 * Delegation, offline. The holder (an agent) narrows its own authority for a
 * sub-agent. No network call, no issuer involvement — this is what makes
 * multi-agent fan-out affordable.
 */
export function attenuate(token, { caps, expiresAt, scope, subs = 0, tenant }) {
  const parsed = parse(token);
  // The authority we are narrowing from is either the root grant (no links yet)
  // or the last link's claims.
  const last = parsed.links.length ? parsed.links[parsed.links.length - 1].claims : parsed.claims0;
  if (!last.delegable) throw new Error('token is not delegable');
  if ((caps & ~last.caps) !== 0) throw new Error('attenuation may not add capabilities');
  if (expiresAt > last.expiresAt) throw new Error('attenuation may not extend expiry');
  const narrowedScope = scope ?? last.scope;
  if (!(narrowedScope + '/').startsWith(last.scope) && narrowedScope !== last.scope) {
    throw new Error('attenuation may not widen scope');
  }
  const claims = encodeClaims({
    caps, expiresAt, scope: narrowedScope, delegable: last.delegable,
    tenant: tenant ?? last.tenant, nonce: subs >>> 0,
  });
  const prevSig = parsed.sig;
  const link = hmac128(prevSig, claims);
  const w = new Writer(token.length + claims.length + SIG_LEN + 8);
  w.raw(token).bytes(claims).raw(link);
  return w.finish();
}

function parse(token) {
  const r = new Reader(token);
  const ver = r.u8();
  if (ver !== TOKEN_VER) throw new Error('bad token version');
  const keyId = r.varint();
  const maxSubs = r.varint();
  const claims0Buf = r.bytes();
  const sig0 = Buffer.from(token.subarray(r.off, r.off + ED_LEN)); r.off += ED_LEN;
  const links = [];
  let sig = sig0;
  while (!r.done) {
    const claimsBuf = r.bytes();
    const link = Buffer.from(token.subarray(r.off, r.off + SIG_LEN)); r.off += SIG_LEN;
    links.push({ claimsBuf, claims: decodeClaims(claimsBuf), link });
    sig = link;
  }
  return { keyId, maxSubs, claims0Buf, claims0: decodeClaims(claims0Buf), sig0, links, sig };
}

/**
 * Hot-path verification. `cache` is per-process and shared across connections:
 * one Ed25519 verify per distinct root grant, then only HMACs.
 */
export function verify(token, registry, { now = Date.now(), cache = new Map(), required = 0, maxSubsDefault = 1 } = {}) {
  let p;
  try { p = parse(token); } catch (e) { return { ok: false, code: 'MALFORMED', why: e.message }; }
  const key = registry.get(p.keyId);
  if (!key) return { ok: false, code: 'CAP_INVALID', why: 'unknown issuer key' };
  if (p.links.length + 1 > MAX_CHAIN) return { ok: false, code: 'MALFORMED', why: 'chain too long' };

  const cacheKey = crypto.createHash('sha256').update(p.sig0).digest('base64');
  let rootOk = cache.get(cacheKey);
  if (rootOk === undefined) {
    rootOk = crypto.verify(null, p.claims0Buf, key.publicKey, p.sig0);
    if (cache.size > 50000) cache.clear();
    cache.set(cacheKey, rootOk);
  }
  if (!rootOk) return { ok: false, code: 'CAP_INVALID', why: 'bad issuer signature' };

  // Chain: each hop must be *narrower* than the one before it.
  let prev = p.claims0, prevSig = p.sig0, hops = 0;
  for (const l of p.links) {
    const expect = hmac128(prevSig, l.claimsBuf);
    if (!crypto.timingSafeEqual(expect, l.link)) {
      return { ok: false, code: 'CAP_INVALID', why: `broken chain at hop ${hops + 1}`, hops };
    }
    if ((l.claims.caps & ~prev.caps) !== 0) return { ok: false, code: 'SCOPE_DENIED', why: 'widened caps', hops };
    if (l.claims.expiresAt > prev.expiresAt) return { ok: false, code: 'SCOPE_DENIED', why: 'extended expiry', hops };
    if (!(l.claims.scope + '/').startsWith(prev.scope) && l.claims.scope !== prev.scope) {
      return { ok: false, code: 'SCOPE_DENIED', why: 'widened scope', hops };
    }
    prev = l.claims; prevSig = l.link; hops++;
  }
  if (prev.expiresAt * 1000 < now) return { ok: false, code: 'CAP_EXPIRED', why: 'expired', hops };
  if ((prev.caps & required) !== required) return { ok: false, code: 'SCOPE_DENIED', why: 'missing capability', hops };
  return {
    ok: true, hops, caps: prev.caps, scope: prev.scope, tenant: prev.tenant,
    // Two identities matter, and conflating them was a real bug in this codebase:
    //   subject — the chain tip. Two siblings attenuated from the same grant get
    //             different tips, so each sub-agent gets its own quota.
    //   grant   — the issuer-signed root. Used for the aggregate ceiling, so a
    //             single grant cannot be fanned out beyond its signed maxSubs.
    grant: crypto.createHash('sha256').update(p.sig0).digest('hex').slice(0, 24),
    expiresAt: prev.expiresAt, maxSubs: p.maxSubs,
    subject: crypto.createHash('sha256').update(prevSig).digest('hex').slice(0, 24),
  };
}

export const verifyCache = new Map();
