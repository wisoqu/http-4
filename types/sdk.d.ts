import type tls from 'node:tls';
import type {
  ResultData, RejectData, RateData, DecodedCost, H4Client, H4Server,
} from './core.js';

export interface H4Response extends Response {
  readonly h4?: {
    result: ResultData | null;
    reject: RejectData | null;
    rate: RateData | null;
    cost: DecodedCost | null;
    virtual?: Record<string, unknown>;
  };
  readonly h4Done?: Promise<{
    payload: Buffer;
    streamId: number;
    result: ResultData | null;
    reject: RejectData | null;
  }>;
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
  constructor(opts: {
    token: Uint8Array | string;
    h4Fetch: H4Fetch;
    budget?: number;
    instanceId?: string;
  });
  delegate(opts?: {
    caps?: number;
    scope?: string;
    expiresAt?: number;
    delegable?: boolean;
    budget?: number;
    instanceId?: string;
  }): AgentSession;
  fetch(url: string | URL, init?: H4RequestInit): Promise<H4Response>;
  stream(url: string | URL, init?: H4RequestInit): AsyncGenerator<Buffer, void, unknown>;
}
