import type { KeyObject } from 'node:crypto';
import type http from 'node:http';
import type http2 from 'node:http2';
import type tls from 'node:tls';

export const isNativeLoaded: boolean;

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

export const CAPS: {
  readonly READ: 1;
  readonly WRITE: 2;
  readonly DELEGATE: 4;
  readonly PAY: 8;
  readonly PUBLISH: 16;
  readonly SUBSCRIBE: 32;
};

export interface IntentData {
  mode?: number;
  idem?: string;
  deadlineMs?: number;
  costCeiling?: number;
  maxShape?: number;
  dedup?: string;
}

export interface CostData {
  predicted?: number;
  costClass?: number;
  effortBits?: number;
  budgetRemaining?: number;
  value?: number;
  tokenBudget?: number;
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

export interface RejectData {
  code: number;
  retryAfterMs: number;
  difficulty: number;
  detail: string;
  poeMode?: 'sha256' | 'memhard';
}

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

export class KeyRegistry {
  add(keyId: number, publicKey: KeyObject | string, opts?: { multiSig?: boolean }): this;
  remove(keyId: number): this;
  revokeGrant(grantId: string): this;
  isGrantRevoked(grantId: string): boolean;
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
): VerifiedIdentity | { ok: false; code: string; why: string; hops?: number };

export class PassIssuer {
  constructor(opts?: {
    secret?: Buffer | Uint8Array | string;
    keyId?: number;
    ttlSec?: number;
    maxRedeemed?: number;
    clock?: () => number;
  });
  mint(opts?: { ttlSec?: number; now?: number }): string;
  mintWallet(count?: number, opts?: { ttlSec?: number; now?: number }): string[];
  redeem(b64: string, opts?: { now?: number }): { ok: boolean; passId?: string; expiresAt?: number; why?: string };
}

export class Limiter {
  budget: number;
  windowMs: number;
  poeMode: 'sha256' | 'memhard';
  passIssuer: PassIssuer | null;
  constructor(opts?: {
    budget?: number;
    windowMs?: number;
    pressure?: () => number;
    netMultiplier?: number;
    poeMode?: 'sha256' | 'memhard';
    passIssuer?: PassIssuer | null;
  });
  static sessionKey(): Buffer;
  static deriveSessionKey(clusterSecret: Buffer | string, peerId: string): Buffer;
}

export function solvePoE(challenge: Uint8Array, bits: number, maxIter?: number, mode?: 'sha256' | 'memhard'): { nonce: number; hash: Buffer } | null;
export function checkPoE(challenge: Uint8Array, nonce: number, bits: number, mode?: 'sha256' | 'memhard'): boolean;
export function memHardHash(challenge: Uint8Array, nonce: number): Buffer;
export function solveMemHard(challenge: Uint8Array, bits: number, maxIter?: number): { nonce: number; hash: Buffer } | null;
export function checkMemHard(challenge: Uint8Array, nonce: number, bits: number): boolean;

export class H4Cache {
  constructor(opts?: { maxEntries?: number; maxBytes?: number; defaultTtlMs?: number; staleGraceMs?: number });
}

export interface H4RouteContext {
  path: string;
  rawPath: string;
  query: string;
  method: string;
  headers: Record<string, string>;
  body: Buffer | null;
  intent: IntentData;
  cost: CostData;
  identity: VerifiedIdentity | null;
  now: number;
  remainingMs: number;
  signal?: AbortSignal;
}

export type H4RouteResult =
  | { status?: number; type?: string; body?: unknown; cost?: number; tokens?: number; ttlMs?: number; stream?: AsyncIterable<Uint8Array | string | object>; costPerChunk?: number }
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
  handle(req: Record<string, unknown>, now?: number): Promise<{ frames: Buffer[]; result?: Record<string, unknown>; reject?: RejectData; cost: number }>;
  handleStream(req: Record<string, unknown>, opts?: { signal?: AbortSignal | null; onFrame?: (frame: Buffer) => void; now?: number }): Promise<{ frames: Buffer[]; result?: Record<string, unknown>; reject?: RejectData; cost: number }>;
  stats(): Record<string, unknown>;
}

export class H4Client {
  constructor(opts?: {
    sessionKey?: Buffer | null;
    budgetPerSec?: number;
    windowMs?: number;
    maxTokenBudget?: number;
    maxInFlight?: number;
    maxEffortBits?: number;
    passWallet?: string[];
    respectCeilings?: boolean;
  });
  addPasses(passes: string | string[]): this;
  takePass(): string | null;
  payEffort(difficulty: { bits?: number; difficulty?: number; challenge?: Uint8Array; detail?: string; mode?: 'sha256' | 'memhard' }): number | null;
}

export interface H4Response extends Response {
  readonly h4?: {
    result: ResultData | null;
    reject: RejectData | null;
    rate: Record<string, number> | null;
    cost: CostData | null;
    virtual?: Record<string, unknown>;
  };
  readonly h4Done?: Promise<{ payload: Buffer; streamId: number; result: ResultData | null; reject: RejectData | null }>;
}

export interface H4RequestInit extends RequestInit {
  h4?: {
    cap?: Uint8Array;
    mode?: number;
    idem?: string;
    deadlineMs?: number;
    costCeiling?: number;
    maxShape?: number;
    dedup?: string;
    predicted?: number;
    costClass?: number;
    worth?: number;
    tokenBudget?: number;
    stream?: boolean;
    earlyData?: boolean;
    checkBudget?: boolean;
  };
}

export interface H4Fetch {
  (input: string | URL | Request, init?: H4RequestInit): Promise<H4Response>;
  client: H4Client;
  close(): Promise<void>;
}

export function createH4Fetch(opts?: {
  server?: H4Server | null;
  tlsOptions?: tls.ConnectionOptions;
  clientOptions?: ConstructorParameters<typeof H4Client>[0];
  defaultCap?: Uint8Array | null;
  passWallet?: string[];
  autoEffort?: boolean;
  maxEffortBits?: number;
  fallbackFetch?: typeof fetch;
}): H4Fetch;

export class AgentSession {
  token: Buffer;
  budget: number;
  spent: number;
  instanceId: string;
  constructor(opts: { token: Uint8Array | string; h4Fetch: H4Fetch; budget?: number; instanceId?: string });
  delegate(opts?: { caps?: number; scope?: string; expiresAt?: number; delegable?: boolean; budget?: number; instanceId?: string }): AgentSession;
  fetch(url: string | URL, init?: H4RequestInit): Promise<H4Response>;
  stream(url: string | URL, init?: H4RequestInit): AsyncGenerator<Buffer, void, unknown>;
}

export function toWebHandler(h4Server: H4Server, opts?: { altSvc?: string | null; maxBodyBytes?: number }): (request: Request, env?: Record<string, unknown>) => Promise<Response>;
export function toNodeMiddleware(h4Server: H4Server, opts?: { maxBodyBytes?: number; passThroughUnmatched?: boolean; altSvc?: string | null }): (req: http.IncomingMessage, res: http.ServerResponse, next?: (err?: unknown) => void) => Promise<void>;
export function wrapFetchHandler(fetchHandler: (req: Request, ctx: H4RouteContext) => Promise<Response>, opts?: { cost?: number; ttlMs?: number }): (ctx: H4RouteContext) => Promise<H4RouteResult>;

export function createServer(opts: {
  handler: H4Server;
  tlsOptions?: tls.TlsOptions;
  metadata?: { serverId?: string };
  clusterSecret?: Buffer | string | null;
  maxFrameBytes?: number;
  handshakeTimeoutMs?: number;
  idleTimeoutMs?: number;
  maxConcurrentStreams?: number;
}): tls.Server;

export function connect(opts: {
  host?: string;
  port: number;
  tlsOptions?: tls.ConnectionOptions;
  agent?: string;
  maxFrameBytes?: number;
  connectTimeoutMs?: number;
}): Promise<{
  handshake: Record<string, unknown>;
  alpnProtocol: string;
  sessionKey: Buffer;
  request(frames: Buffer, opts?: { virtual?: Record<string, unknown> | null }): Promise<{ virtual: unknown; payload: Buffer | null; streamId?: number }>;
  subscribe(frames: Buffer, opts?: { onData?: (chunk: Buffer) => void; onHeaders?: (headers: [string, string][]) => void; signal?: AbortSignal | null }): Promise<{ payload: Buffer; streamId: number; result: ResultData | null; reject: RejectData | null }>;
  cancel(streamId: number, code?: number): void;
  close(): void;
}>;

export function createGateway(opts: { handler: H4Server; altSvcPort?: number | null; maxBodyBytes?: number }): http.Server;
export function createH2Gateway(opts: { handler: H4Server; tlsOptions?: tls.TlsOptions | null; altSvcPort?: number | null; maxBodyBytes?: number }): http2.Http2Server | http2.Http2SecureServer;
export function encodeH3CompatFlight(h4FlightOrFrames: Buffer | Buffer[]): Buffer;
export function decodeH3CompatFlight(h3Buf: Buffer, opts?: { maxFrameLen?: number; maxFrames?: number }): Buffer;
export function normalizePeerIp(ip?: string | null): string;
