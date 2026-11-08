// ─────────────────────────────────────────────────────────────────────────────
// H4 identity: capability tokens that agents can *delegate offline*.
//
//   signedRoot:  ver ‖ keyId ‖ maxSubs ‖ claims0
//   root grant:  signedRoot ‖ Ed25519_issuer("H4-CAP-ROOT-v1\0" ‖ signedRoot)
//   attenuation: link_i = HMAC128( sig_{i-1} , "H4-CAP-LINK-v1|" ‖ claims_i )
//   token      = signedRoot ‖ sig0 ‖ (claims1 ‖ link1) ‖ …
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import { Writer, Reader } from './varint.js';
import { nativeBinding } from './native.js';

export const CAPS = { READ: 1, WRITE: 2, DELEGATE: 4, PAY: 8, PUBLISH: 16, SUBSCRIBE: 32 };
export const TOKEN_VER = 1;
export const MAX_CHAIN = 6;

const SIG_LEN = 16;
const ED_LEN = 64;

const ROOT_DOMAIN = Buffer.from('H4-CAP-ROOT-v1\u0000');
const LINK_DOMAIN = Buffer.from('H4-CAP-LINK-v1|');

const enc = new TextEncoder();
const dec = new TextDecoder();

export function isValidPath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.charCodeAt(0) !== 47) return false;
  if (p.includes('\u0000') || p.includes('\r') || p.includes('\n') || p.includes('\\')) return false;
  if (p.includes('%')) {
    const lower = p.toLowerCase();
    if (
      lower.includes('%2e') || lower.includes('%2f') ||
      lower.includes('%5c') || lower.includes('%00') ||
      lower.includes('%0d') || lower.includes('%0a')
    ) {
      return false;
    }
  }
  const segs = p.split('/');
  for (let i = 1; i < segs.length; i++) {
    if (segs[i] === '..' || segs[i] === '.') return false;
  }
  return true;
}

export function isSubScope(parentScope, childPath) {
  if (!isValidPath(parentScope) || !isValidPath(childPath)) return false;
  if (parentScope === '/') return true;
  const p = parentScope.length > 1 && parentScope.endsWith('/')
    ? parentScope.slice(0, -1)
    : parentScope;
  return childPath === p || childPath.startsWith(p + '/');
}

export class KeyRegistry {
  constructor() {
    this.keys = new Map();
    this.revokedGrants = new Set();
  }
  add(keyId, publicKey, { multiSig = false } = {}) {
    const der = typeof publicKey.export === 'function'
      ? publicKey.export({ type: 'spki', format: 'der' })
      : Buffer.from(String(publicKey));
    const pubFp = crypto.createHash('sha256').update(der).digest().subarray(0, 16);
    this.keys.set(keyId, { publicKey, multiSig, pubFp });
    return this;
  }
  remove(keyId) {
    this.keys.delete(keyId);
    return this;
  }
  revokeGrant(grantId) {
    if (this.revokedGrants.size >= 100000) {
      this.revokedGrants.delete(this.revokedGrants.values().next().value);
    }
    this.revokedGrants.add(grantId);
    return this;
  }
  isGrantRevoked(grantId) {
    return this.revokedGrants.has(grantId);
  }
  get(keyId) { return this.keys.get(keyId); }
}

function encodeClaims({ caps = 0, expiresAt = 0, scope = '/', delegable = 0, tenant = '', nonce = 0 }) {
  if (tenant.includes('\u0000') || tenant.includes('\r') || tenant.includes('\n')) {
    throw new RangeError('invalid control characters in tenant');
  }
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
  if (claims.tenant.includes('\u0000') || claims.tenant.includes('\r') || claims.tenant.includes('\n')) {
    throw new RangeError('invalid tenant characters');
  }
  return claims;
}

export function hmacLinkJs(prevSig, claimsBuf) {
  return crypto.createHmac('sha256', prevSig)
    .update(LINK_DOMAIN)
    .update(claimsBuf)
    .digest()
    .subarray(0, SIG_LEN);
}

function hmac128(prevSig, claimsBuf) {
  if (nativeBinding) {
    return nativeBinding.hmacSha256(prevSig, LINK_DOMAIN, claimsBuf, SIG_LEN);
  }
  return hmacLinkJs(prevSig, claimsBuf);
}

/** Issuer side: mint a domain-separated root grant. */
export function mintRoot({ keyId, privateKey, caps, expiresAt, scope = '/', delegable = 1, tenant = '', maxSubs = 0 }) {
  if (!isValidPath(scope)) throw new Error('invalid root scope');
  const claims = encodeClaims({ caps, expiresAt, scope, delegable: delegable ? 1 : 0, tenant, nonce: 0 });
  const head = new Writer(32 + claims.length);
  head.u8(TOKEN_VER).varint(keyId).varint(maxSubs).bytes(claims);
  const signedRoot = head.finish();
  const toSign = Buffer.concat([ROOT_DOMAIN, signedRoot]);
  const sig = crypto.sign(null, toSign, privateKey);
  const w = new Writer(signedRoot.length + sig.length);
  w.raw(signedRoot).raw(sig);
  return w.finish();
}

/** Offline delegation: narrow authority without contacting the issuer. */
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
  const link = hmac128(parsed.sig, claims);
  const w = new Writer(token.length + claims.length + SIG_LEN + 8);
  w.raw(token).bytes(claims).raw(link);
  return w.finish();
}

function parse(token) {
  if (!(token instanceof Uint8Array) || token.length < 1 + 1 + 1 + 1 + ED_LEN || token.length > 8192) {
    throw new RangeError('truncated, oversized, or non-binary token');
  }
  const r = new Reader(token);
  const ver = r.u8();
  if (ver !== TOKEN_VER) throw new Error('bad token version');
  const keyId = r.varint();
  const maxSubs = r.varint();
  const claims0Buf = r.bytes();
  const signedRoot = token.subarray(0, r.off);
  const sig0 = Buffer.from(r.slice(ED_LEN));
  const linksOffset = r.off;
  const packedLinks = token.subarray(linksOffset);
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
  return { keyId, maxSubs, signedRoot, claims0Buf, claims0, sig0, packedLinks, links, sig };
}

/** Hot-path verification with native C HMAC-chain acceleration and revocation check. */
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
      const toVerify = Buffer.concat([ROOT_DOMAIN, p.signedRoot]);
      rootOk = crypto.verify(null, toVerify, key.publicKey, p.sig0);
    } catch {
      rootOk = false;
    }
    if (rootOk) {
      if (cache.size >= 50000) cache.delete(cache.keys().next().value);
      cache.set(cacheKey, true);
    }
  }
  if (!rootOk) return { ok: false, code: 'CAP_INVALID', why: 'bad issuer signature' };

  const grant = crypto.createHash('sha256').update(p.signedRoot).update(p.sig0).digest('hex').slice(0, 24);
  if (typeof registry.isGrantRevoked === 'function' && registry.isGrantRevoked(grant)) {
    return { ok: false, code: 'CAP_INVALID', why: 'grant revoked' };
  }

  // Verify HMAC links: C fast-path checks all HMACs in one N-API call, JS checks monotonic policy
  let prev = p.claims0, prevSig = p.sig0, hops = 0;
  if (nativeBinding && p.links.length > 0) {
    for (const l of p.links) {
      if (!prev.delegable) {
        return { ok: false, code: 'SCOPE_DENIED', why: 'non-delegable parent token', hops };
      }
      prev = l.claims;
      hops++;
    }
    const macRes = nativeBinding.verifyCapLinks(p.sig0, LINK_DOMAIN, p.packedLinks);
    if (macRes.rc !== 1) {
      return { ok: false, code: 'CAP_INVALID', why: `broken chain at hop ${macRes.hops + 1}`, hops: macRes.hops };
    }
    // Check monotonic narrowing hop-by-hop
    prev = p.claims0;
    hops = 0;
    for (const l of p.links) {
      if ((l.claims.caps & ~prev.caps) !== 0) return { ok: false, code: 'SCOPE_DENIED', why: 'widened caps', hops };
      if (l.claims.expiresAt > prev.expiresAt) return { ok: false, code: 'SCOPE_DENIED', why: 'extended expiry', hops };
      if (!isSubScope(prev.scope, l.claims.scope)) return { ok: false, code: 'SCOPE_DENIED', why: 'widened scope', hops };
      if (prev.tenant !== '' && l.claims.tenant !== prev.tenant) return { ok: false, code: 'SCOPE_DENIED', why: 'changed tenant', hops };
      if (l.claims.delegable && !prev.delegable) return { ok: false, code: 'SCOPE_DENIED', why: 're-enabled delegation', hops };
      prev = l.claims;
      prevSig = l.link;
      hops++;
    }
  } else {
    for (const l of p.links) {
      if (!prev.delegable) {
        return { ok: false, code: 'SCOPE_DENIED', why: 'non-delegable parent token', hops };
      }
      const expect = hmacLinkJs(prevSig, l.claimsBuf);
      if (!crypto.timingSafeEqual(expect, l.link)) {
        return { ok: false, code: 'CAP_INVALID', why: `broken chain at hop ${hops + 1}`, hops };
      }
      if ((l.claims.caps & ~prev.caps) !== 0) return { ok: false, code: 'SCOPE_DENIED', why: 'widened caps', hops };
      if (l.claims.expiresAt > prev.expiresAt) return { ok: false, code: 'SCOPE_DENIED', why: 'extended expiry', hops };
      if (!isSubScope(prev.scope, l.claims.scope)) return { ok: false, code: 'SCOPE_DENIED', why: 'widened scope', hops };
      if (prev.tenant !== '' && l.claims.tenant !== prev.tenant) return { ok: false, code: 'SCOPE_DENIED', why: 'changed tenant', hops };
      if (l.claims.delegable && !prev.delegable) return { ok: false, code: 'SCOPE_DENIED', why: 're-enabled delegation', hops };
      prev = l.claims;
      prevSig = l.link;
      hops++;
    }
  }

  if (prev.expiresAt * 1000 < now) return { ok: false, code: 'CAP_EXPIRED', why: 'expired', hops };
  if ((prev.caps & required) !== required) return { ok: false, code: 'SCOPE_DENIED', why: 'missing capability', hops };
  return {
    ok: true, hops, caps: prev.caps, scope: prev.scope, tenant: prev.tenant,
    delegable: prev.delegable,
    grant,
    expiresAt: prev.expiresAt, maxSubs: p.maxSubs,
    subject: crypto.createHash('sha256').update(prevSig).digest('hex').slice(0, 24),
  };
}

export const verifyCache = new Map();
