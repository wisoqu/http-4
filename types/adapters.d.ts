import type http from 'node:http';
import type tls from 'node:tls';
import type { H4Server, H4RouteContext, H4RouteResult, KeyRegistry } from './core.js';
import type { PassIssuer } from './privacy-pass.js';

export function toWebHandler(
  h4Server: H4Server,
  opts?: { altSvc?: string | null; maxBodyBytes?: number }
): (request: Request, env?: Record<string, unknown>) => Promise<Response>;

export function toNodeMiddleware(
  h4Server: H4Server,
  opts?: { maxBodyBytes?: number; passThroughUnmatched?: boolean; altSvc?: string | null }
): (req: http.IncomingMessage, res: http.ServerResponse, next?: (err?: unknown) => void) => Promise<void>;

export function wrapFetchHandler(
  fetchHandler: (req: Request, ctx: H4RouteContext) => Promise<Response>,
  opts?: { cost?: number; ttlMs?: number }
): (ctx: H4RouteContext) => Promise<H4RouteResult>;

export function h4Shield(opts?: {
  server?: H4Server | null;
  budget?: number;
  windowMs?: number;
  pressure?: () => number;
  poeMode?: 'sha256' | 'memhard';
  passIssuer?: PassIssuer | null;
  registry?: KeyRegistry;
  requireCap?: boolean;
  altSvc?: string | null;
}): ((req: http.IncomingMessage, res: http.ServerResponse, next?: (err?: unknown) => void) => void) & { server: H4Server };

export function withH4(
  fetchHandler: (req: Request, ctx: H4RouteContext) => Promise<Response>,
  opts?: {
    budget?: number;
    windowMs?: number;
    pressure?: () => number;
    poeMode?: 'sha256' | 'memhard';
    passIssuer?: PassIssuer | null;
    defaultTtlMs?: number;
    maxCacheBytes?: number;
    cost?: number;
    registry?: KeyRegistry;
    requireCap?: boolean;
    altSvc?: string | null;
  }
): ((request: Request, env?: Record<string, unknown>) => Promise<Response>) & { server: H4Server };

export function createReverseProxy(opts: {
  upstream: string | URL;
  budget?: number;
  windowMs?: number;
  pressure?: () => number;
  poeMode?: 'sha256' | 'memhard';
  passIssuer?: PassIssuer | null;
  defaultTtlMs?: number;
  requireCap?: boolean;
  registry?: KeyRegistry;
  altSvcPort?: number | null;
  upstreamFetch?: typeof fetch;
}): {
  h4Server: H4Server;
  httpGateway: http.Server;
  createTlsServer(tlsOptions: tls.TlsOptions): tls.Server;
};
