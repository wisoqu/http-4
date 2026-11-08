import type tls from 'node:tls';
import type {
  HeaderPair, DecodedIntent, DecodedCost, DecodedCapFrame,
  ResultData, RejectData, HelloData, H4Server,
} from './core.js';

export const PROTO: 'h4/1';
export const ALPN_PROTOCOLS: readonly ['h4', 'h4/1'];
export const CLIENT_CONTROL_STREAM: 2;
export const SERVER_CONTROL_STREAM: 3;

export class MessageParser {
  maxFrameBytes: number;
  maxBufferBytes: number;
  constructor(
    onMessage: (streamId: number, payload: Buffer) => void,
    opts?: { maxFrameBytes?: number; maxBufferBytes?: number }
  );
  push(chunk: Uint8Array): void;
}

export function packMessage(streamId: number, frames: Uint8Array): Buffer;

export interface DecodedH4Request {
  headers: HeaderPair[];
  intent: DecodedIntent;
  cost: DecodedCost;
  cap?: DecodedCapFrame;
  rate: { receipt: string; mac: string } | null;
  effortNonce?: number;
  pass?: string;
  body: Buffer | null;
  peer: string;
  byteLength: number;
}

export function decodeRequest(framesBuf: Uint8Array, peer: string): DecodedH4Request;

export function createServer(opts: {
  handler: H4Server;
  tlsOptions?: tls.TlsOptions;
  metadata?: { serverId?: string };
  clusterSecret?: Uint8Array | string | null;
  maxFrameBytes?: number;
  handshakeTimeoutMs?: number;
  idleTimeoutMs?: number;
  maxConcurrentStreams?: number;
  strictAlpn?: boolean;
}): tls.Server;

export interface H4WireConnection {
  handshake: HelloData;
  alpnProtocol: string;
  sessionKey: Buffer;
  readonly streamSeq: number;
  readonly pendingCount: number;
  request(
    frames: Uint8Array,
    opts?: { virtual?: Record<string, unknown> | null }
  ): Promise<{ virtual: Record<string, unknown> | null; payload: Buffer | null; streamId?: number }>;
  subscribe(
    frames: Uint8Array,
    opts?: {
      onData?: (chunk: Buffer) => void;
      onHeaders?: (headers: HeaderPair[]) => void;
      signal?: AbortSignal | null;
    }
  ): Promise<{ payload: Buffer; streamId: number; result: ResultData | null; reject: RejectData | null }>;
  cancel(streamId: number, code?: number): void;
  close(): void;
}

export function connect(opts: {
  host?: string;
  port: number;
  tlsOptions?: tls.ConnectionOptions;
  agent?: string;
  maxFrameBytes?: number;
  connectTimeoutMs?: number;
}): Promise<H4WireConnection>;
