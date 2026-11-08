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
//   signedRoot:  ver ‖ keyId ‖ maxSubs ‖ claims0
//   root grant:  signedRoot ‖ Ed25519_issuer(signedRoot)
//   attenuation: link_i = HMAC128( sig_{i-1} , claims_i )
//   token      = signedRoot ‖ sig0 ‖ (claims1 ‖ link1) ‖ …
//
// Security argument (why this is safe even though link salts are public):
//   * authority comes only from the issuer signature over signedRoot (covering
//     ver, keyId, maxSubs, and claims0), verified once per grant and cached by
//     (pubKey, signedRoot, sig0) → one Ed25519 verify per *grant*, not per request;
//   * each hop MUST narrow the previous hop: parent.delegable === 1,
//     caps ⊆ caps, expiry ≤ expiry, tenant immutable (once bound), and scope is
//     a segment-safe path prefix extension. Widening is rejected at verify time.
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { Writer, Reader } from './varint.js';

export const CAPS = { READ: 1, WRITE: 2, DELEGATE: 4, PAY: 8, PUBLISH: 16, SUBSCRIBE: 32 };
export const TOKEN_VER = 1;
export const MAX_CHAIN = 6; // 6 hops is ~1000× more than any real agent topology

const SIG_LEN = 16;   // truncated HMAC128 per link: enough, and keeps tokens tiny
const ED_LEN = 64;

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * Validate a clean absolute URL path without dot-segment traversal or control bytes.
 */
export function isValidPath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.charCodeAt(0) !== 47) return false;
  if (p.includes('\u0000') || p.includes('\\')) return false;
  if (p.includes('%')) {
    const lower = p.toLowerCase();
    if (lower.includes('%2e') || lower.includes('%2f') || lower.includes('%5c') || lower.includes('%00')) {
      return false;
    }
  }
  const segs = p.split('/');
  for (let i = 1; i < segs.length; i++) {
    if (segs[i] === '..' || segs[i] === '.') return false;
  }
  return true;
}

/**
 * Segment-aware scope containment: `/v1/items` covers `/v1/items` and `/v1/items/42`,
 * never `/v1/items-secret` or `/v1/items/../admin`.
 */
export function isSubScope(parentScope, childPath) {
  if (!isValidPath(parentScope) || !isValidPath(childPath)) return false;
  if (parentScope === '/') return true;
  const p = parentScope.length > 1 && parentScope.endsWith('/')
    ? parentScope.slice(0, -1)
    : parentScope;
  return childPath === p || childPath.startsWith(p + '/');
}

export class KeyRegistry {
  constructor() { this.keys = new Map(); }
  add(keyId, publicKey, { multiSig = false } = {}) {
    const der = typeof publicKey.export === 'function'
      ? publicKey.export({ type: 'spki', format: 'der' })
      : Buffer.from(String(publicKey));
    const pubFp = crypto.createHash('sha256').update(der).digest().subarray(0, 16);
    this.keys.set(keyId, { publicKey, multiSig, pubFp });
    return this;
  }
  get(keyId) { return this.keys.get(keyId); }
}

// NOTE on `nonce`: without it, two siblings attenuated from the same grant with
// identical claims encode to identical bytes — hence identical tokens, hence
// (because the quota key is the chain tip) one shared quota. Requiring a nonce
// is what makes "one token per instance" representable at all.
function encodeClaims({ caps = 0, expiresAt = 0, scope = '/', delegable = 0, tenant = '', nonce = 0 }) {
  const w = new Writer(96);
  w.varint(caps)
    .varint(expiresAt)
    .bytes(enc.encode(scope))
    .u8(delegable ? 1 : 0)
    .bytes(enc.encode(tenant))
    .varint(nonce >>> 0);
  return w.finish();
}

function decodeClaims(buf) {
  const r = new Reader(buf);
  const claims = {
    caps: r.varint(),
    expiresAt: r.varint(),
    scope: dec.decode(r.bytes()),
    delegable: r.u8(),
    tenant: dec.decode(r.bytes()),
    nonce: r.done ? 0 : r.varint(),
  };
  if (!r.done) throw new RangeError('trailing bytes in claims');
  if (claims.delegable !== 0 && claims.delegable !== 1) throw new RangeError('invalid delegable flag');
  return claims;
}

/** Issuer side: mint a root grant. Signs ver + keyId + maxSubs + claims0 together. */
export function mintRoot({ keyId, privateKey, caps, expiresAt, scope = '/', delegable = 1, tenant = '', maxSubs = 0 }) {
  if (!isValidPath(scope)) throw new Error('invalid root scope');
  const claims = encodeClaims({ caps, expiresAt, scope, delegable: delegable ? 1 : 0, tenant, nonce: 0 });
  const head = new Writer(32 + claims.length);
  head.u8(TOKEN_VER).varint(keyId).varint(maxSubs).bytes(claims);
  const signedRoot = head.finish();
  const sig = crypto.sign(null, signedRoot, privateKey);
  const w = new Writer(signedRoot.length + sig.length);
  w.raw(signedRoot).raw(sig);
  return w.finish();
}

function hmac128(key, msg) {
  return crypto.createHmac('sha256', key).update(msg).digest().subarray(0, SIG_LEN);
}

/**
 * Delegation, offline. The holder (an agent) narrows its own authority for a
 * sub-agent. No network call, no issuer involvement.
 */
export function attenuate(token, { caps, expiresAt, scope, subs = 0, tenant, delegable }) {
  const parsed = parse(token);
  if (parsed.links.length + 1 >= MAX_CHAIN) throw new Error('attenuation chain exceeds MAX_CHAIN');
  const last = parsed.links.length ? parsed.links[parsed.links.length - 1].claims : parsed.claims0;
  if (!last.delegable) throw new Error('token is not delegable');
  const nextCaps = caps ?? last.caps;
  const nextExp = expiresAt ?? last.expiresAt;
  if ((nextCaps & ~last.caps) !== 0) throw new Error('attenuation may not add capabilities');
  if (nextExp > last.expiresAt) throw new Error('attenuation may not extend expiry');
  const narrowedScope = scope ?? last.scope;
  if (!isSubScope(last.scope, narrowedScope)) {
    throw new Error('attenuation may not widen scope');
  }
  const nextTenant = tenant ?? last.tenant;
  if (last.tenant !== '' && nextTenant !== last.tenant) {
    throw new Error('attenuation may not change tenant');
  }
  const nextDelegable = delegable === undefined ? last.delegable : (delegable ? 1 : 0);
  if (nextDelegable && !last.delegable) throw new Error('attenuation may not re-enable delegation');

  const claims = encodeClaims({
    caps: nextCaps,
    expiresAt: nextExp,
    scope: narrowedScope,
    delegable: nextDelegable,
    tenant: nextTenant,
    nonce: subs >>> 0,
  });
  const prevSig = parsed.sig;
  const link = hmac128(prevSig, claims);
  const w = new Writer(token.length + claims.length + SIG_LEN + 8);
  w.raw(token).bytes(claims).raw(link);
  return w.finish();
}

function parse(token) {
  if (!(token instanceof Uint8Array) || token.length < 1 + 1 + 1 + 1 + ED_LEN) {
    throw new RangeError('truncated or non-binary token');
  }
  const r = new Reader(token);
  const ver = r.u8();
  if (ver !== TOKEN_VER) throw new Error('bad token version');
  const keyId = r.varint();
  const maxSubs = r.varint();
  const claims0Buf = r.bytes();
  const signedRoot = token.subarray(0, r.off);
  const sig0 = Buffer.from(r.slice(ED_LEN));
  const claims0 = decodeClaims(claims0Buf);
  if (!isValidPath(claims0.scope)) throw new Error('invalid root scope');

  const links = [];
  let sig = sig0;
  while (!r.done) {
    if (links.length >= MAX_CHAIN) throw new Error('chain too long');
    const claimsBuf = r.bytes();
    const link = Buffer.from(r.slice(SIG_LEN));
    links.push({ claimsBuf, claims: decodeClaims(claimsBuf), link });
    sig = link;
  }
  return { keyId, maxSubs, signedRoot, claims0Buf, claims0, sig0, links, sig };
}

/**
 * Hot-path verification. `cache` is per-process and shared across connections:
 * one Ed25519 verify per distinct verified root grant, then only HMACs.
 */
export function verify(token, registry, { now = Date.now(), cache = new Map(), required = 0 } = {}) {
  let p;
  try { p = parse(token); } catch (e) { return { ok: false, code: 'MALFORMED', why: e.message }; }
  const key = registry.get(p.keyId);
  if (!key) return { ok: false, code: 'CAP_INVALID', why: 'unknown issuer key' };
  if (p.links.length + 1 > MAX_CHAIN) return { ok: false, code: 'MALFORMED', why: 'chain too long' };

  const cacheKey = crypto.createHash('sha256')
    .update(key.pubFp)
    .update(p.signedRoot)
    .update(p.sig0)
    .digest('base64');

  let rootOk = cache.get(cacheKey);
  if (rootOk === undefined) {
    try {
      rootOk = crypto.verify(null, p.signedRoot, key.publicKey, p.sig0);
    } catch {
      rootOk = false;
    }
    // Only cache positive verifications so invalid tokens cannot pollute/evict valid grants.
    if (rootOk) {
      if (cache.size >= 50000) cache.delete(cache.keys().next().value);
      cache.set(cacheKey, true);
    }
  }
  if (!rootOk) return { ok: false, code: 'CAP_INVALID', why: 'bad issuer signature' };

  // Chain: each hop must be *narrower* than the one before it.
  let prev = p.claims0, prevSig = p.sig0, hops = 0;
  for (const l of p.links) {
    if (!prev.delegable) {
      return { ok: false, code: 'SCOPE_DENIED', why: 'non-delegable parent token', hops };
    }
    const expect = hmac128(prevSig, l.claimsBuf);
    if (!crypto.timingSafeEqual(expect, l.link)) {
      return { ok: false, code: 'CAP_INVALID', why: `broken chain at hop ${hops + 1}`, hops };
    }
    if ((l.claims.caps & ~prev.caps) !== 0) return { ok: false, code: 'SCOPE_DENIED', why: 'widened caps', hops };
    if (l.claims.expiresAt > prev.expiresAt) return { ok: false, code: 'SCOPE_DENIED', why: 'extended expiry', hops };
    if (!isSubScope(prev.scope, l.claims.scope)) {
      return { ok: false, code: 'SCOPE_DENIED', why: 'widened scope', hops };
    }
    if (prev.tenant !== '' && l.claims.tenant !== prev.tenant) {
      return { ok: false, code: 'SCOPE_DENIED', why: 'changed tenant', hops };
    }
    if (l.claims.delegable && !prev.delegable) {
      return { ok: false, code: 'SCOPE_DENIED', why: 're-enabled delegation', hops };
    }
    prev = l.claims; prevSig = l.link; hops++;
  }
  if (prev.expiresAt * 1000 < now) return { ok: false, code: 'CAP_EXPIRED', why: 'expired', hops };
  if ((prev.caps & required) !== required) return { ok: false, code: 'SCOPE_DENIED', why: 'missing capability', hops };
  return {
    ok: true, hops, caps: prev.caps, scope: prev.scope, tenant: prev.tenant,
    delegable: prev.delegable,
    grant: crypto.createHash('sha256').update(p.signedRoot).update(p.sig0).digest('hex').slice(0, 24),
    expiresAt: prev.expiresAt, maxSubs: p.maxSubs,
    subject: crypto.createHash('sha256').update(prevSig).digest('hex').slice(0, 24),
  };
}

export const verifyCache = new Map();
