#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// `http4` Zero-Code CLI:
//   npx http4 doctor
//   npx http4 proxy --upstream http://127.0.0.1:8000 --port 8080 [--budget 200] [--ttl 5000]
//   npx http4 keygen
//   npx http4 mint --private-key <b64url-der> [--scope /v1] [--caps read,write] [--ttl 3600]
// ─────────────────────────────────────────────────────────────────────────────

import crypto from 'node:crypto';
import {
  CAPS, KeyRegistry, mintRoot, solvePoE, isNativeLoaded, createReverseProxy,
} from '../src/index.js';

const args = process.argv.slice(2);
const cmd = args[0] || 'help';

function flag(name, fallback = undefined) {
  const idx = args.indexOf(`--${name}`);
  if (idx === -1) return fallback;
  const next = args[idx + 1];
  return next === undefined || next.startsWith('--') ? true : next;
}

if (cmd === 'doctor') {
  const ch = Buffer.alloc(32, 9);
  const t0 = process.hrtime.bigint();
  const iters = 100_000;
  solvePoE(ch, 30, iters);
  const sec = Number(process.hrtime.bigint() - t0) / 1e9;
  const rateM = (iters / sec / 1e6).toFixed(2);
  console.log('HTTP/4 Doctor');
  console.log(`  node          ${process.version}`);
  console.log(`  platform      ${process.platform}/${process.arch}`);
  console.log(`  c11_napi      ${isNativeLoaded ? 'ACTIVE (native/bin/h4_native.node)' : 'pure-JS fallback'}`);
  console.log(`  poe_hashrate  ${rateM} M hashes/s (1 core)`);
  console.log('  status        READY');
  process.exit(0);
}

if (cmd === 'keygen') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const privB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url');
  console.log(JSON.stringify({ keyId: 1, publicKeySpkiB64: pubB64, privateKeyPkcs8B64: privB64 }, null, 2));
  process.exit(0);
}

if (cmd === 'mint') {
  const privB64 = flag('private-key');
  if (!privB64) {
    console.error('Error: --private-key <base64url-pkcs8> is required (run `npx http4 keygen` first).');
    process.exit(1);
  }
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privB64, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  });
  const keyId = Number(flag('key-id', '1'));
  const scope = String(flag('scope', '/'));
  const ttl = Number(flag('ttl', '3600'));
  const tenant = String(flag('tenant', ''));
  const maxSubs = Number(flag('max-subs', '8'));
  const capNames = String(flag('caps', 'read,write,delegate,subscribe')).split(',').map((s) => s.trim().toUpperCase());
  let caps = 0;
  for (const name of capNames) {
    if (CAPS[name] !== undefined) caps |= CAPS[name];
  }
  const token = mintRoot({
    keyId,
    privateKey,
    caps,
    expiresAt: Math.floor(Date.now() / 1000) + ttl,
    scope,
    tenant,
    maxSubs,
    delegable: (caps & CAPS.DELEGATE) ? 1 : 0,
  });
  console.log(token.toString('base64url'));
  process.exit(0);
}

if (cmd === 'proxy') {
  const upstream = flag('upstream');
  if (!upstream) {
    console.error('Error: --upstream <http://host:port> is required.\nExample: npx http4 proxy --upstream http://127.0.0.1:8000 --port 8080');
    process.exit(1);
  }
  const port = Number(flag('port', process.env.PORT || '8080'));
  const host = String(flag('host', '0.0.0.0'));
  const budget = Number(flag('budget', '200'));
  const windowMs = Number(flag('window-ms', '10000'));
  const defaultTtlMs = Number(flag('ttl-ms', '0'));
  const poeMode = String(flag('poe-mode', 'sha256'));
  const pubKeyB64 = flag('public-key', process.env.H4_PUBLIC_KEY);
  const requireCap = Boolean(flag('require-cap', false));

  const registry = new KeyRegistry();
  if (pubKeyB64) {
    const pubKey = crypto.createPublicKey({
      key: Buffer.from(pubKeyB64, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    registry.add(Number(flag('key-id', '1')), pubKey);
  }

  const { httpGateway } = createReverseProxy({
    upstream,
    budget,
    windowMs,
    defaultTtlMs,
    poeMode,
    registry,
    requireCap,
  });

  httpGateway.listen(port, host, () => {
    console.log(`[http4 proxy] listening on http://${host}:${port} -> upstream ${upstream}`);
    console.log(`[http4 proxy] C11 N-API=${isNativeLoaded} · budget=${budget}/${windowMs}ms · poe=${poeMode} · requireCap=${requireCap}`);
  });
} else {
  console.log(`http4 CLI (v0.2.0) — Zero-code sidecar & token toolkit

Usage:
  npx http4 doctor
  npx http4 proxy --upstream http://127.0.0.1:8000 [--port 8080] [--budget 200] [--ttl-ms 5000] [--poe-mode sha256|memhard]
  npx http4 keygen
  npx http4 mint --private-key <b64url> [--scope /v1] [--caps read,write,delegate] [--ttl 3600]`);
}
