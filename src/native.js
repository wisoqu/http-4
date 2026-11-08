// ─────────────────────────────────────────────────────────────────────────────
// H4 Native C11 / Node-API Accelerator loader with seamless pure-JS fallback.
//
// Set `H4_PURE_JS=1` to force the pure-JS code path (used for differential
// fuzzing and cross-platform parity verification).
// ─────────────────────────────────────────────────────────────────────────────

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { buildNative } from '../scripts/build-native.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const addonPath = path.join(root, 'native', 'bin', 'h4_native.node');
const require = createRequire(import.meta.url);

let binding = null;
const skipNative = process.env.H4_PURE_JS === '1' || process.env.H4_SKIP_NATIVE === '1';
if (!skipNative) {
  try {
    if (!fs.existsSync(addonPath)) {
      buildNative({ quiet: true });
    }
    if (fs.existsSync(addonPath)) {
      binding = require(addonPath);
    }
  } catch {
    binding = null;
  }
}

export const nativeBinding = binding;
export const isNativeLoaded = Boolean(binding);
