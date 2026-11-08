/// <reference types="node" />
import type { KeyObject } from 'node:crypto';
import type { PassIssuer } from './privacy-pass.js';

// ── Varint & binary cursor (`src/varint.js`) ─────────────────────────────────
export const MAX_VARINT: bigint;
export function varintSize(v: number | bigint): 1 | 2 | 4 | 8;
export function writeVarint(buf: Buffer, off: number, v: number | bigint): number;
export function readVarint(buf: Uint8Array, off?: number): { value: number; size: 1 | 2 | 4 | 8 };
export function readVarintBig(buf: Uint8Array, off?: number): { value: bigint; size: 1 | 2 | 4 | 8 };
export function zigzag(n: number): number | bigint;
export function unzigzag(u: number | bigint): number;

export class Writer {
  buf: Buffer;
  off: number;
  constructor(size?: number);
  varint(v: number | bigint): this;
  bytes(b: Uint8Array): this;
  raw(b: Uint8Array): this;
  u8(v: number): this;
  finish(): Buffer;
}

export class Reader {
  buf: Uint8Array;
  off: number;
  constructor(buf: Uint8Array);
  varint(): number;
  bytes(): Uint8Array;
  slice(n: number): Uint8Array;
  u8(): number;
  readonly remaining: number;
  readonly done: boolean;
}

// ── Static-first header compression (`src/headers.js`) ───────────────────────
export type HeaderPair = [string, string];
export type HeaderInput = ReadonlyArray<readonly [string, string | number]> | Record<string, string | number>;

export const TABLE_VERSION: 1;
export const MAX_HEADER_BYTES: number;
export const STATIC_TABLE: ReadonlyArray<readonly [string, string]>;
export const VALUE_PREFIXES: ReadonlyArray<string>;

export function encodeHeaders(headers: HeaderInput): Buffer;
export function decodeHeaders(buf: Uint8Array, opts?: { maxHeaders?: number; maxBytes?: number }): HeaderPair[];
export function toObject(list: Iterable<readonly [string, string]>): Record<string, string>;

// ── Frame types & codecs (`src/frames.js`) ───────────────────────────────────
export const F: {
  readonly HEADERS: 0;
  readonly DATA: 1;
  readonly INTENT: 2;
  readonly COST: 3;
  readonly CAP: 4;
  readonly RESULT: 5;
  readonly RATE: 6;
  readonly CANCEL: 7;
  readonly REJECT: 8;
  readonly PATH: 9;
  readonly ACCESS: 10;
  readonly PING: 11;
  readonly GOAWAY: 12;
  readonly HELLO: 13;
};

export const REJECT: {
  readonly OK: 0;
  readonly RATE_LIMITED: 1;
  readonly BUDGET_EXHAUSTED: 2;
  readonly EFFORT_REQUIRED: 3;
  readonly CAP_INVALID: 4;
  readonly CAP_EXPIRED: 5;
  readonly SCOPE_DENIED: 6;
  readonly AGENT_UNKNOWN: 7;
  readonly COST_REFUSED: 8;
  readonly MALFORMED: 9;
  readonly DEFERRED: 10;
};

export const CACHE: {
  readonly MISS: 0;
  readonly HIT: 1;
  readonly HIT_STALE: 2;
  readonly REVALIDATED: 3;
  readonly MEMO: 4;
  readonly COMPUTED: 5;
};

export const MODE: {
  readonly QUERY: 0;
  readonly MUTATE: 1;
  readonly SUBSCRIBE: 2;
};

export const CLASS: {
  readonly CHEAP: 0;
  readonly NORMAL: 1;
  readonly EXPENSIVE: 2;
};

export interface IntentData {
  mode?: number;
  idem?: string;
  deadlineMs?: number;
  costCeiling?: number;
  maxShape?: number;
  dedup?: string;
}

export interface DecodedIntent {
  mode: number;
  idem: string;
  deadlineMs: number;
  costCeiling: number;
  maxShape: number;
  dedup: string;
}

export interface CostData {
  predicted?: number;
  costClass?: number;
  effortBits?: number;
  budgetRemaining?: number;
  value?: number;
  tokenBudget?: number;
}

export interface DecodedCost {
  predicted: number;
  costClass: number;
  effortBits: number;
  budgetRemaining: number;
  value: number;
  tokenBudget: number;
}

export interface CapFrameData {
  token?: Uint8Array;
  expiresAt?: number;
  caps?: number;
  scope?: string;
  delegable?: number | boolean;
}

export interface DecodedCapFrame {
  token: Buffer;
  expiresAt: number;
  caps: number;
  scope: string;
  delegable: number;
}

export interface ResultData {
  status: number;
  costActual: number;
  cache: number;
  tokens: number;
  memoReuse: number;
  wallMs: number;
  costAsym: number;
  flags: number;
}

export interface RateData {
  pressure: number;
  budgetRemaining: number;
  refillPerSec: number;
  blockUntilMs: number;
  penaltyMs: number;
}

export interface RejectData {
  code: number;
  retryAfterMs: number;
  difficulty: number;
  detail: string;
  poeMode?: 'sha256' | 'memhard';
}

export interface HelloData {
  proto: string;
  tableVersion: number;
  ratePolicy: { budget: number; windowMs: number };
  sessionKey: Buffer;
  serverId: string;
  agent: string;
}

export interface AccessData {
  tier: string;
  cache: number;
  costActual: number;
  predicted: number;
  wallUs: number;
}

export interface RawFrame {
  type: number;
  payload: Uint8Array;
}

export function frame(type: number, payload: Uint8Array | string): Buffer;
export function encodeIntent(opts?: IntentData): Buffer;
export function decodeIntent(buf: Uint8Array): DecodedIntent;
export function encodeCost(opts?: CostData): Buffer;
export function decodeCost(buf: Uint8Array): DecodedCost;
export function encodeCap(opts?: CapFrameData): Buffer;
export function decodeCap(buf: Uint8Array): DecodedCapFrame;
export function encodeResult(opts?: Partial<ResultData>): Buffer;
export function decodeResult(buf: Uint8Array): ResultData;
export function encodeRate(opts?: Partial<RateData>): Buffer;
export function decodeRate(buf: Uint8Array): RateData;
export function encodeReject(code: number, opts?: { retryAfterMs?: number; difficulty?: number; detail?: string }): Buffer;
export function decodeReject(buf: Uint8Array): RejectData;
export function encodeHello(opts?: {
  proto?: string;
  tableVersion?: number;
  budget?: number;
  windowMs?: number;
  sessionKey?: Uint8Array | string;
  serverId?: string;
  agent?: string;
}): Buffer;
export function decodeHello(buf: Uint8Array): HelloData;
export function encodeAccess(opts?: Partial<AccessData>): Buffer;
export function decodeAccess(buf: Uint8Array): AccessData;
export function encodeCancel(opts?: { code?: number }): Buffer;
export function decodeCancel(buf: Uint8Array): { code: number };
export function encodePath(opts?: { hint?: string }): Buffer;
export function decodePath(buf: Uint8Array): { hint: string };
export function encodePing(opts?: { id?: number }): Buffer;
export function decodePing(buf: Uint8Array): { id: number };
export function encodeGoaway(opts?: { lastStream?: number; reason?: number }): Buffer;
export function decodeGoaway(buf: Uint8Array): { lastStream: number; reason: number };
export function encodeHeadersFrame(headers: HeaderInput): Buffer;
export function decodeHeadersFrame(buf: Uint8Array): HeaderPair[];
export function encodeData(buf: Uint8Array | string): Buffer;
export function iterFrames(buf: Uint8Array): Generator<RawFrame, void, unknown>;
export function splitFramesIncremental(buf: Uint8Array): { frames: RawFrame[]; rest: Uint8Array };

// ── Capability identity & offline delegation (`src/identity.js`) ─────────────
export const CAPS: {
  readonly READ: 1;
  readonly WRITE: 2;
  readonly DELEGATE: 4;
  readonly PAY: 8;
  readonly PUBLISH: 16;
  readonly SUBSCRIBE: 32;
};
export const TOKEN_VER: 1;
export const MAX_CHAIN: 6;
export const verifyCache: Map<string, boolean>;

export function isValidPath(p: string): boolean;
export function isSubScope(parentScope: string, childPath: string): boolean;
export function hmacLinkJs(prevSig: Uint8Array, claimsBuf: Uint8Array): Buffer;

export interface VerifiedIdentity {
  ok: true;
  hops: number;
  caps: number;
  scope: string;
  tenant: string;
  delegable: number;
  grant: string;
  expiresAt: number;
  maxSubs: number;
  subject: string;
}

export interface FailedIdentity {
  ok: false;
  code: string;
  why: string;
  hops?: number;
}

export class KeyRegistry {
  add(keyId: number, publicKey: KeyObject | string, opts?: { multiSig?: boolean }): this;
  remove(keyId: number): this;
  revokeGrant(grantId: string): this;
  isGrantRevoked(grantId: string): boolean;
  get(keyId: number): { publicKey: KeyObject | string; multiSig: boolean; pubFp: Buffer } | undefined;
}

export function mintRoot(opts: {
  keyId: number;
  privateKey: KeyObject;
  caps: number;
  expiresAt: number;
  scope?: string;
  delegable?: number | boolean;
  tenant?: string;
  maxSubs?: number;
}): Buffer;

export function attenuate(token: Uint8Array, opts: {
  caps?: number;
  expiresAt?: number;
  scope?: string;
  subs?: number;
  tenant?: string;
  delegable?: number | boolean;
}): Buffer;

export function verify(
  token: Uint8Array,
  registry: KeyRegistry,
  opts?: { now?: number; cache?: Map<string, boolean>; required?: number }
): VerifiedIdentity | FailedIdentity;

// ── Cooperative rate limiting & Proof-of-Effort (`src/limits.js`) ────────────
export const CLASS_WEIGHT: Record<number, number>;

export interface ReceiptPayload {
  ver?: number;
  window: number;
  spent: number;
  blockedUntil: number;
  nonce: number;
}

export function encodeReceipt(r: ReceiptPayload): string;
export function decodeReceipt(s: string): Required<ReceiptPayload> | null;
export function signReceipt(receipt: string, key: Uint8Array | string): string;
export function verifyReceipt(receiptStr: string, macStr: string, key: Uint8Array | string): Required<ReceiptPayload> | null;
export function poeChallenge(subject: string, window: number, mode?: 'sha256' | 'memhard'): Buffer;
export function hasLeadingZeroBits(buf: Uint8Array, bits: number): boolean;
export function memHardHashJs(challenge: Uint8Array, nonce: number): Buffer;
export function memHardHash(challenge: Uint8Array, nonce: number): Buffer;
export function solveMemHard(challenge: Uint8Array, bits: number, maxIter?: number): { nonce: number; hash: Buffer } | null;
export function checkMemHard(challenge: Uint8Array, nonce: number, bits: number): boolean;
export function solvePoE(challenge: Uint8Array, bits: number, maxIter?: number, mode?: 'sha256' | 'memhard'): { nonce: number; hash: Buffer } | null;
export function checkPoE(challenge: Uint8Array, nonce: number, bits: number, mode?: 'sha256' | 'memhard'): boolean;

export interface LimitDecision {
  allow: boolean;
  code: string;
  pressure: number;
  tier: string[];
  budgetRemaining?: number;
  effectiveBudget?: number;
  blockUntilMs?: number;
  retryAfterMs?: number;
  difficulty?: number;
  poeMode?: 'sha256' | 'memhard';
}

export class Limiter {
  budget: number;
  windowMs: number;
  poeMode: 'sha256' | 'memhard';
  passIssuer: PassIssuer | null;
  stats: {
    receiptsOk: number;
    receiptsMissing: number;
    receiptsForged: number;
    rejected: number;
    poeServed: number;
    poeRedeemed: number;
    passRedeemed: number;
    hmacOps: number;
  };
  constructor(opts?: {
    budget?: number;
    windowMs?: number;
    pressure?: () => number;
    netMultiplier?: number;
    poeMode?: 'sha256' | 'memhard';
    passIssuer?: PassIssuer | null;
  });
  check(input: {
    subject: string;
    net?: string | null;
    netAllowance?: number;
    costClass?: number;
    receipt?: string | null;
    mac?: string | null;
    sessionKey?: Uint8Array | null;
    identityTrusted?: boolean;
    earlyData?: boolean;
  }, now?: number): LimitDecision;
  redeemPass(input: {
    subject: string;
    net?: string | null;
    passToken: string;
    costClass?: number;
  }, now?: number): LimitDecision | null;
  redeemPoE(input: {
    subject: string;
    net?: string | null;
    poeWindow: number;
    challenge: Uint8Array;
    nonce: number;
    difficulty: number;
    costClass?: number;
    mode?: 'sha256' | 'memhard';
  }, now?: number): LimitDecision | null;
  refund(input: { subject: string; net?: string | null; units?: number }, now?: number): void;
  static sessionKey(): Buffer;
  static deriveSessionKey(clusterSecret: Uint8Array | string, peerId: string): Buffer;
}

// ── Coalescing & pressure-aware cache (`src/cache.js`) ───────────────────────
export function hashKey(...parts: unknown[]): string;

export interface CacheEntry<T = unknown> {
  value: T;
  expiresAt: number;
  size: number;
  computeMs: number;
  memo: boolean;
  tags: string[];
  hits: number;
  stale?: boolean;
}

export class H4Cache {
  maxBytes: number;
  bytes: number;
  defaultTtlMs: number;
  stats: {
    hits: number;
    misses: number;
    coalesced: number;
    evictions: number;
    stored: number;
    savedComputeMs: number;
  };
  constructor(opts?: { maxBytes?: number; defaultTtlMs?: number; pressure?: () => number });
  key(parts: unknown[]): string;
  get<T = unknown>(k: string, now?: number): CacheEntry<T> | null;
  set<T = unknown>(k: string, value: T, opts?: { ttlMs?: number; computeMs?: number; memo?: boolean; tags?: string[]; now?: number }): CacheEntry<T> | null;
  coalesce<T>(k: string, fn: () => Promise<T> | T): Promise<{ value: T; coalesced: boolean }>;
  sizeInfo(): { entries: number; bytes: number; hits: number; misses: number; coalesced: number; evictions: number; stored: number; savedComputeMs: number };
}

// ── Server & Client (`src/server.js`, `src/client.js`) ───────────────────────
export function normalizePeerIp(ip?: string | null): string;

export interface H4RouteContext {
  path: string;
  rawPath: string;
  query: string;
  method: string;
  headers: Record<string, string>;
  params: Record<string, string>;
  body: Buffer | null;
  intent: IntentData;
  cost: CostData;
  identity: VerifiedIdentity | null;
  now: number;
  remainingMs: number;
  signal?: AbortSignal;
}

export type H4RouteResult =
  | {
      status?: number;
      type?: string;
      headers?: HeaderPair[] | Record<string, string>;
      body?: unknown;
      cost?: number;
      tokens?: number;
      ttlMs?: number;
      stream?: AsyncIterable<Uint8Array | string | object>;
      costPerChunk?: number;
    }
  | AsyncIterable<Uint8Array | string | object>;

export class H4Server {
  registry: KeyRegistry;
  limiter: Limiter;
  cache: H4Cache;
  constructor(opts?: {
    routes?: Record<string, (ctx: H4RouteContext) => Promise<H4RouteResult> | H4RouteResult>;
    registry?: KeyRegistry;
    limiter?: Limiter;
    cache?: H4Cache;
    accessLog?: unknown[] | null;
    requireCap?: boolean;
    emitAccess?: boolean;
  });
  route(method: string, path: string, handler: (ctx: H4RouteContext) => Promise<H4RouteResult> | H4RouteResult): this;
  handle(req: Record<string, unknown>, now?: number): Promise<{ frames: Buffer[]; result?: ResultData; reject?: RejectData; cost: number }>;
  handleStream(req: Record<string, unknown>, opts?: { signal?: AbortSignal | null; onFrame?: (frame: Buffer) => void; now?: number }): Promise<{ frames: Buffer[]; result?: ResultData; reject?: RejectData; cost: number }>;
  stats(): Record<string, unknown>;
}

export interface H4ObservedResponse {
  result: ResultData | null;
  rate: RateData | null;
  cost: DecodedCost | null;
  headers: HeaderPair[];
  reject: RejectData | null;
  access: AccessData | null;
  body: Buffer;
}

export class H4Client {
  sessionKey: Buffer | null;
  windowMs: number;
  budget: number;
  maxTokenBudget: number;
  maxInFlight: number;
  maxEffortBits: number;
  passWallet: string[];
  respectCeilings: boolean;
  readonly window: number;
  constructor(opts?: {
    sessionKey?: Buffer | null;
    budgetPerSec?: number;
    windowMs?: number;
    maxTokenBudget?: number;
    maxInFlight?: number;
    maxEffortBits?: number;
    passWallet?: string[];
    log?: unknown[];
    respectCeilings?: boolean;
    key?: { publicKey: KeyObject; privateKey: KeyObject } | null;
  });
  provision(opts: { budget?: number; windowMs?: number; refillPerSec?: number }): this;
  addPasses(passes: string | string[]): this;
  predictCost(opts?: { path?: string; method?: string; intent?: IntentData; cost?: CostData }): number;
  shouldSend(opts: { path?: string; method?: string; intent?: IntentData; cost?: CostData; worth?: number }):
    | { send: false; reason: string; retryAfterMs?: number; predicted?: number; worth?: number }
    | null;
  build(opts: {
    path: string;
    method?: string;
    headers?: HeaderPair[];
    intent?: IntentData;
    cost?: CostData;
    cap?: CapFrameData | null;
    body?: Uint8Array | string | null;
    effortNonce?: number;
    pass?: string;
  }): { frames: Buffer; receipt: string; mac: string; virtualWeight: number };
  observe(respFrames: Uint8Array, opts?: { path?: string | null; method?: string }): H4ObservedResponse;
  takePass(): string | null;
  payEffort(difficulty: {
    bits?: number;
    difficulty?: number;
    challenge?: Uint8Array;
    detail?: string;
    mode?: 'sha256' | 'memhard';
    poeMode?: 'sha256' | 'memhard';
  }): number | null;
}
