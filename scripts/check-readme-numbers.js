#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// CI guardrail: verifies that documentation numbers, test suite counts,
// TypeScript subpath declarations, and claim disclaimers match live code.
// ─────────────────────────────────────────────────────────────────────────────

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');

// 1. Live deterministic CGNAT simulation (`node bench/attack-sim.js --json`)
const rawJson = execFileSync(process.execPath, [path.join(root, 'bench', 'attack-sim.js'), '--json'], {
  encoding: 'utf8',
});
const sim = JSON.parse(rawJson);

assert.equal(sim.requests, 40000);
assert.equal(sim.agentsPerAddress, 69);
assert.equal(sim.classicalPerIp.honestServedPct, 6);
assert.equal(sim.classicalPerIp.honestBlockedPct, 94);
assert.equal(sim.http4.honestServedPct, 50);
assert.equal(sim.http4.honestSelfBlocked, 2500);
assert.equal(sim.http4.attackerServedPct, 1.1);
assert.equal(sim.http4.attackerEffort, 34600);

const fmtComma = (n) => n.toLocaleString('en-US');

for (const doc of ['README.md', 'README.ru.md']) {
  const txt = read(doc);
  assert.ok(txt.includes(fmtComma(sim.requests)), `${doc}: missing request count ${fmtComma(sim.requests)}`);
  assert.ok(txt.includes(`${sim.agentsPerAddress}`), `${doc}: missing agentsPerAddress ${sim.agentsPerAddress}`);
  assert.ok(txt.includes(`${sim.classicalPerIp.honestServedPct.toFixed(1)}%`), `${doc}: missing classical honest %`);
  assert.ok(txt.includes(`${sim.classicalPerIp.honestBlockedPct.toFixed(1)}%`), `${doc}: missing classical blocked %`);
  assert.ok(txt.includes(`${sim.http4.honestServedPct.toFixed(1)}%`), `${doc}: missing http4 honest %`);
  assert.ok(txt.includes(fmtComma(sim.http4.honestSelfBlocked)), `${doc}: missing client-side self-blocked count`);
  assert.ok(txt.includes(`${sim.http4.attackerServedPct.toFixed(1)}%`), `${doc}: missing http4 attacker %`);
  assert.ok(txt.includes(fmtComma(sim.http4.attackerEffort)), `${doc}: missing attacker effort count`);

  // Ensure stale numbers never regress
  assert.ok(!txt.includes('12.0% → 100.0%'), `${doc}: contains stale 12.0% -> 100.0% claim`);
  assert.ok(!txt.includes('2.3%'), `${doc}: contains stale 2.3% claim`);
}

// 2. Sync live executed test counts between test/*.js and docs
const unitOut = execFileSync(process.execPath, [path.join(root, 'test', 'run.js')], { encoding: 'utf8' });
const secOut = execFileSync(process.execPath, [path.join(root, 'test', 'security-audit.js')], { encoding: 'utf8' });
const unitCount = Number((unitOut.match(/(\d+)\s+passed,\s*0\s+failed/) || [])[1]);
const secCount = Number((secOut.match(/(\d+)\s+passed,\s*0\s+failed/) || [])[1]);
assert.ok(unitCount > 0 && secCount > 0, `failed to parse executed test counts (${unitCount}, ${secCount})`);

for (const doc of ['README.md', 'README.ru.md', 'SECURITY.md', 'spec/http4.md']) {
  const txt = read(doc);
  assert.ok(
    txt.includes(`${unitCount}`) && txt.includes(`${secCount}`),
    `${doc}: expected test counts ${unitCount} and ${secCount}`
  );
}

// 3. Guard against forbidden overclaims / missing disclaimers
const docsToScan = ['README.md', 'README.ru.md', 'SECURITY.md', 'docs/INTEGRATION.md', 'spec/http4.md', 'package.json'];
for (const doc of docsToScan) {
  const txt = read(doc);
  assert.ok(!/over QUIC/i.test(txt), `${doc}: must not claim 'over QUIC' as accomplished transport`);
  assert.ok(!/mathematically impossible/i.test(txt), `${doc}: must not claim 'mathematically impossible'`);
  assert.ok(!/математически невозможно/i.test(txt), `${doc}: must not claim 'математически невозможно'`);
}

for (const doc of ['README.md', 'README.ru.md', 'SECURITY.md', 'spec/http4.md', 'src/privacy-pass.js', 'types/privacy-pass.d.ts']) {
  const txt = read(doc);
  assert.ok(txt.includes('9576'), `${doc}: must explicitly disclaim RFC 9576-9578 Privacy Pass equivalence`);
}

// 4. Verify package.json subpath "types" conditions & root export coverage
const pkg = JSON.parse(read('package.json'));
for (const [subpath, target] of Object.entries(pkg.exports)) {
  assert.equal(typeof target, 'object', `exports["${subpath}"] must be an object with "types" and "import"`);
  assert.ok(target.types, `exports["${subpath}"] missing "types" condition`);
  assert.ok(fs.existsSync(path.join(root, target.types)), `missing types file ${target.types} for ${subpath}`);
  assert.ok(fs.existsSync(path.join(root, target.import)), `missing import file ${target.import} for ${subpath}`);
}

const allDts = fs.readdirSync(path.join(root, 'types'))
  .filter((f) => f.endsWith('.d.ts'))
  .map((f) => read(path.join('types', f)))
  .join('\n');

const rootMod = await import(path.join(root, 'src', 'index.js'));
const missingTypes = Object.keys(rootMod).filter((sym) => !new RegExp(`\\b${sym}\\b`).test(allDts));
assert.deepEqual(missingTypes, [], `Untyped root exports: ${missingTypes.join(', ')}`);

console.log(
  `[check-readme] ok — attack-sim (${sim.requests} reqs, ${sim.http4.honestServedPct}% honest / ${sim.http4.attackerServedPct}% attacker), ` +
  `tests (${unitCount}+${secCount}), ${Object.keys(pkg.exports).length} typed subpaths, ${Object.keys(rootMod).length} root exports verified.`
);
