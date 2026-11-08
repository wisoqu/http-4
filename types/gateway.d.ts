import type http from 'node:http';
import type http2 from 'node:http2';
import type tls from 'node:tls';
import type {
  HeaderPair, DecodedCost, ResultData, RateData, RejectData, H4Server,
} from './core.js';
import type { DecodedH4Request } from './wire.js';

export function extractH4Request(
  method: string,
  url: string,
  rawHeaders: Record<string, string | string[] | undefined>,
  bodyBuf?: Buffer | null,
  peer?: string | null
): DecodedH4Request & { earlyData?: boolean };

export function unpackH4Response(resFrames: Buffer[]): {
  result: ResultData | null;
  rate: RateData | null;
  cost: DecodedCost | null;
  reject: RejectData | null;
  headers: HeaderPair[];
  body: Buffer;
};

export function createGateway(opts: {
  handler: H4Server;
  altSvcPort?: number | null;
  maxBodyBytes?: number;
}): http.Server;

export function createH2Gateway(opts: {
  handler: H4Server;
  tlsOptions?: tls.TlsOptions | null;
  altSvcPort?: number | null;
  maxBodyBytes?: number;
}): http2.Http2Server | http2.Http2SecureServer;
