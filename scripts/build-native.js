#!/usr/bin/env node
// Zero-dependency builder & ASan/UBSan runner for the H4 C11 / Node-API accelerator.
//
//   node scripts/build-native.js              # build native/bin/h4_native.node (graceful fallback)
//   H4_SKIP_NATIVE=1 npm install              # skip native compilation and use pure-JS fallback
//   node scripts/build-native.js --san        # run C11 suite under ASan + UBSan

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function isSkipRequested() {
  const v = process.env.H4_SKIP_NATIVE ?? process.env.npm_config_h4_skip_native ?? '';
  return v === '1' || v.toLowerCase() === 'true';
}

function findCompiler() {
  for (const cc of [process.env.CC, 'gcc', 'clang', 'cc'].filter(Boolean)) {
    try {
      execFileSync(cc, ['--version'], { stdio: 'ignore' });
      return cc;
    } catch {
      // try next
    }
  }
  return null;
}

function findNodeInclude() {
  const candidates = [
    process.env.NODE_INCLUDE_DIR,
    path.resolve(process.execPath, '../../include/node'),
    '/usr/local/include/node',
    '/usr/include/node',
  ].filter(Boolean);
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, 'node_api.h'))) return dir;
  }
  return null;
}

export function buildNative({ quiet = false } = {}) {
  if (isSkipRequested()) {
    if (!quiet) console.log('[h4-native] H4_SKIP_NATIVE=1 — skipping native build, using pure-JS fallback.');
    return null;
  }
  const cc = findCompiler();
  const nodeInc = findNodeInclude();
  if (!cc || !nodeInc) {
    if (!quiet) console.log('[h4-native] C compiler or node_api.h not found — using pure-JS fallback.');
    return null;
  }
  const outDir = path.join(root, 'native', 'bin');
  const outPath = path.join(outDir, 'h4_native.node');

  const flags = [
    '-std=c11', '-O3', '-fPIC',
    '-Wall', '-Wextra', '-Werror',
    `-I${nodeInc}`,
  ];
  if (process.platform === 'darwin') {
    flags.push('-dynamiclib', '-Wl,-undefined,dynamic_lookup');
  } else {
    flags.push('-shared');
  }

  try {
    fs.mkdirSync(outDir, { recursive: true });
    execFileSync(cc, [
      ...flags,
      path.join(root, 'native', 'h4_core.c'),
      path.join(root, 'native', 'h4_napi.c'),
      '-o', outPath,
    ], { stdio: 'pipe' });
  } catch {
    if (!quiet) console.log('[h4-native] native build failed — using pure-JS fallback.');
    return null;
  }

  if (!quiet) {
    console.log(`[h4-native] built ${path.relative(root, outPath)} (${cc}, N-API v8)`);
  }
  return outPath;
}

export function runSanitizerSuite() {
  const cc = findCompiler();
  if (!cc) throw new Error('No C compiler found for sanitizer suite');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'h4-san-'));
  const bin = path.join(tmpDir, 'h4_san_test');
  try {
    execFileSync(cc, [
      '-std=c11', '-O2', '-g', '-fno-omit-frame-pointer',
      '-Wall', '-Wextra', '-Werror',
      '-fsanitize=address,undefined',
      path.join(root, 'native', 'h4_core.c'),
      path.join(root, 'native', 'test_san.c'),
      '-o', bin,
    ], { stdio: 'inherit' });
    execFileSync(bin, [], {
      stdio: 'inherit',
      env: { ...process.env, UBSAN_OPTIONS: 'print_stacktrace=1:halt_on_error=1', ASAN_OPTIONS: 'detect_leaks=1:halt_on_error=1' },
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes('--san')) {
    runSanitizerSuite();
  } else {
    buildNative();
  }
}
