/// <reference types="node" />
export interface H4NativeBinding {
  sha256(msg: Uint8Array): Buffer;
  hmacSha256(key: Uint8Array, domain: Uint8Array, msg: Uint8Array, truncLen?: number): Buffer;
  verifyCapLinks(sig0: Uint8Array, domain: Uint8Array, packedLinks: Uint8Array): { rc: number; hops: number };
  solvePoE(challenge: Uint8Array, bits: number, maxIter?: number): { nonce: number; hash: Buffer } | null;
  checkPoE(challenge: Uint8Array, nonce: number, bits: number): boolean;
  memHardHash(challenge: Uint8Array, nonce: number): Buffer;
  solveMemHard(challenge: Uint8Array, bits: number, maxIter?: number): { nonce: number; hash: Buffer } | null;
  checkMemHard(challenge: Uint8Array, nonce: number, bits: number): boolean;
  scanFrames(buf: Uint8Array): { complete: Float64Array; restOffset: number };
}

export const nativeBinding: H4NativeBinding | null;
export const isNativeLoaded: boolean;
