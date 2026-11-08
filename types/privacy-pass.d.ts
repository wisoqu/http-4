/// <reference types="node" />
/**
 * H4 single-use HMAC-SHA256-192 overload pass (`h4-pass` header).
 *
 * NOTE: Despite the historical module path `http4/privacy-pass`, these tokens
 * do NOT implement IETF Privacy Pass (RFC 9576–9578) blind signatures / VOPRF.
 * `passId` is visible at both issuance and redemption (issuer-linkable).
 */
export const PASS_VER: 1;

export interface PassRedeemResult {
  ok: boolean;
  passId?: string;
  expiresAt?: number;
  why?: string;
}

export class PassIssuer {
  keyId: number;
  ttlSec: number;
  maxRedeemed: number;
  constructor(opts?: {
    secret?: Buffer | Uint8Array | string;
    keyId?: number;
    ttlSec?: number;
    maxRedeemed?: number;
    clock?: () => number;
  });
  mint(opts?: { ttlSec?: number; now?: number }): string;
  mintWallet(count?: number, opts?: { ttlSec?: number; now?: number }): string[];
  redeem(b64: string, opts?: { now?: number }): PassRedeemResult;
}
