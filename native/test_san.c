#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h4_core.h"

static uint32_t xorshift32(uint32_t *state) {
  uint32_t x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *state = x;
  return x;
}

int main(void) {
  /* 1. NIST FIPS 180-4 SHA-256 test vector ("abc") */
  static const uint8_t expect_abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  };
  uint8_t digest[32];
  h4_sha256((const uint8_t *)"abc", 3, digest);
  assert(h4_ct_equal(digest, expect_abc, 32) == 1);

  /* 2. RFC 4231 Test Case 2 HMAC-SHA256 ("Jefe", "what do ya want for nothing?") */
  static const uint8_t expect_hmac[32] = {
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
    0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
    0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
    0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
  };
  const char *msg = "what do ya want for nothing?";
  h4_hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)msg, 9, (const uint8_t *)(msg + 9), strlen(msg) - 9, digest);
  assert(h4_ct_equal(digest, expect_hmac, 32) == 1);

  /* 3. Boundary varint & ZigZag tests (including INT64_MIN edge checks) */
  const uint64_t bounds[] = {
    0, 1, 63, 64, 16383, 16384,
    UINT64_C(1073741823), UINT64_C(1073741824),
    H4_MAX_VARINT
  };
  for (size_t i = 0; i < sizeof(bounds) / sizeof(bounds[0]); i++) {
    uint8_t vbuf[8];
    size_t sz = h4_varint_encode(vbuf, sizeof(vbuf), bounds[i]);
    assert(sz >= 1 && sz <= 8);
    uint64_t back = 0;
    assert(h4_varint_decode(vbuf, sz, &back) == sz);
    assert(back == bounds[i]);
    /* Truncated buffer must fail cleanly with 0 */
    assert(h4_varint_decode(vbuf, sz - 1, &back) == 0);
  }
  assert(h4_varint_encode(digest, 8, H4_MAX_VARINT + 1) == 0);

  const int64_t zz_vals[] = {
    0, -1, 1, -1000, 1000, -1500000000LL, 1500000000LL,
    -(1LL << 40), (1LL << 40)
  };
  for (size_t i = 0; i < sizeof(zz_vals) / sizeof(zz_vals[0]); i++) {
    uint64_t z = 0;
    assert(h4_zigzag_encode(zz_vals[i], &z) == 1);
    assert(h4_zigzag_decode(z) == zz_vals[i]);
  }
  uint64_t z_min = 0;
  assert(h4_zigzag_encode(INT64_MIN, &z_min) == 0); /* Exceeds 62-bit varint */

  /* 4. PoE & Memory-Hard solve + verify */
  const uint8_t chal[32] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  uint64_t nonce = 0;
  uint8_t h_out[32];
  assert(h4_poe_solve(chal, 32, 10, 1000000, &nonce, h_out) == 1);
  assert(h4_poe_verify(chal, 32, nonce, 10) == 1);

  uint64_t mh_nonce = 0;
  assert(h4_memhard_solve(chal, 32, 8, 1000000, &mh_nonce, h_out) == 1);
  assert(h4_memhard_verify(chal, 32, mh_nonce, 8) == 1);

  /* 5. 100,000-iteration ASan + UBSan hostile binary fuzzer */
  uint32_t rng = 0xdeadbeefu;
  uint64_t triples[64 * 3];
  uint8_t tip[16];
  size_t hops = 0;
  for (int iter = 0; iter < 100000; iter++) {
    size_t len = (size_t)(xorshift32(&rng) % 192u);
    /* Heap-allocate exact `len` so ASan catches even a 1-byte out-of-bounds read! */
    uint8_t *fuzz = len ? (uint8_t *)malloc(len) : NULL;
    for (size_t j = 0; j < len; j++) {
      fuzz[j] = (uint8_t)(xorshift32(&rng) & 0xffu);
    }

    uint64_t v = 0;
    (void)h4_varint_decode(fuzz, len, &v);
    (void)h4_scan_frames(fuzz, len, triples, 64);
    (void)h4_verify_cap_links(chal, 32, (const uint8_t *)"H4-CAP-LINK-v1|", 15, fuzz, len, tip, &hops);

    free(fuzz);
  }

  printf("ASan + UBSan C11 suite passed: NIST SHA-256, RFC 4231 HMAC, varints, PoE, MemHard, 100,000 heap-bounded fuzz cases.\n");
  return 0;
}
