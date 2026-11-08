#include "h4_core.h"
#include <stdlib.h>
#include <string.h>

static void write_u32_be(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v);
}

static uint32_t read_u32_be(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) |
         ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  |
         ((uint32_t)p[3]);
}

static void write_nonce_pair(uint8_t out8[8], uint64_t nonce) {
  /* Matches JS layout: bytes 0..3 = low32 BE, bytes 4..7 = high32 BE */
  write_u32_be(out8, (uint32_t)(nonce & UINT32_C(0xffffffff)));
  write_u32_be(out8 + 4, (uint32_t)(nonce >> 32));
}

int h4_ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  if (a == NULL || b == NULL) return 0;
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  return diff == 0 ? 1 : 0;
}

size_t h4_varint_encode(uint8_t *out, size_t out_cap, uint64_t val) {
  if (out == NULL || val > H4_MAX_VARINT) return 0;
  if (val < UINT64_C(0x40)) {
    if (out_cap < 1) return 0;
    out[0] = (uint8_t)val;
    return 1;
  }
  if (val < UINT64_C(0x4000)) {
    if (out_cap < 2) return 0;
    out[0] = (uint8_t)(0x40u | ((val >> 8) & 0x3fu));
    out[1] = (uint8_t)(val & 0xffu);
    return 2;
  }
  if (val < UINT64_C(0x40000000)) {
    if (out_cap < 4) return 0;
    write_u32_be(out, (uint32_t)(val | UINT64_C(0x80000000)));
    return 4;
  }
  if (out_cap < 8) return 0;
  uint64_t tagged = val | UINT64_C(0xc000000000000000);
  write_u32_be(out, (uint32_t)(tagged >> 32));
  write_u32_be(out + 4, (uint32_t)(tagged & UINT32_C(0xffffffff)));
  return 8;
}

size_t h4_varint_decode(const uint8_t *in, size_t in_len, uint64_t *val_out) {
  if (in == NULL || val_out == NULL || in_len == 0) return 0;
  uint8_t b0 = in[0];
  uint8_t p = b0 >> 6;
  if (p == 0) {
    *val_out = (uint64_t)(b0 & 0x3fu);
    return 1;
  }
  if (p == 1) {
    if (in_len < 2) return 0;
    *val_out = ((uint64_t)(b0 & 0x3fu) << 8) | (uint64_t)in[1];
    return 2;
  }
  if (p == 2) {
    if (in_len < 4) return 0;
    *val_out = (uint64_t)(read_u32_be(in) & UINT32_C(0x3fffffff));
    return 4;
  }
  if (in_len < 8) return 0;
  uint64_t hi = (uint64_t)(read_u32_be(in) & UINT32_C(0x3fffffff));
  uint64_t lo = (uint64_t)read_u32_be(in + 4);
  *val_out = (hi << 32) | lo;
  return 8;
}

int h4_zigzag_encode(int64_t n, uint64_t *out) {
  if (out == NULL) return 0;
  uint64_t z;
  if (n < 0) {
    /* Avoid signed negation UB on INT64_MIN */
    uint64_t mag = (uint64_t)(-(n + 1)) + UINT64_C(1);
    if (mag > (H4_MAX_VARINT + UINT64_C(1)) / UINT64_C(2)) return 0;
    z = (mag << 1) - UINT64_C(1);
  } else {
    uint64_t mag = (uint64_t)n;
    if (mag > H4_MAX_VARINT / UINT64_C(2)) return 0;
    z = mag << 1;
  }
  if (z > H4_MAX_VARINT) return 0;
  *out = z;
  return 1;
}

int64_t h4_zigzag_decode(uint64_t u) {
  uint64_t half = u >> 1;
  if (u & UINT64_C(1)) {
    return -(int64_t)half - 1;
  }
  return (int64_t)half;
}

/* ── Portable FIPS 180-4 SHA-256 (zero UB, 100% ASan/UBSan verified) ──────── */

static const uint32_t K256[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

typedef struct {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t buf[64];
  size_t buflen;
} sha256_ctx_t;

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) w[i] = read_u32_be(block + i * 4);
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
  uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + S1 + ch + K256[i] + w[i];
    uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
  ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
  ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
  ctx->bitlen = 0;
  ctx->buflen = 0;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
  if (len == 0 || data == NULL) return;
  for (size_t i = 0; i < len; i++) {
    ctx->buf[ctx->buflen++] = data[i];
    if (ctx->buflen == 64) {
      sha256_transform(ctx, ctx->buf);
      ctx->bitlen += 512;
      ctx->buflen = 0;
    }
  }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t out[H4_SHA256_LEN]) {
  uint64_t total_bits = ctx->bitlen + (uint64_t)ctx->buflen * 8u;
  ctx->buf[ctx->buflen++] = 0x80u;
  if (ctx->buflen > 56) {
    while (ctx->buflen < 64) ctx->buf[ctx->buflen++] = 0;
    sha256_transform(ctx, ctx->buf);
    ctx->buflen = 0;
  }
  while (ctx->buflen < 56) ctx->buf[ctx->buflen++] = 0;
  write_u32_be(ctx->buf + 56, (uint32_t)(total_bits >> 32));
  write_u32_be(ctx->buf + 60, (uint32_t)(total_bits & UINT32_C(0xffffffff)));
  sha256_transform(ctx, ctx->buf);
  for (int i = 0; i < 8; i++) write_u32_be(out + i * 4, ctx->state[i]);
}

void h4_sha256(const uint8_t *data, size_t len, uint8_t out[H4_SHA256_LEN]) {
  sha256_ctx_t ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, out);
}

static void sha256_3parts(
    const uint8_t *p1, size_t l1,
    const uint8_t *p2, size_t l2,
    const uint8_t *p3, size_t l3,
    uint8_t out[H4_SHA256_LEN]) {
  sha256_ctx_t ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, p1, l1);
  sha256_update(&ctx, p2, l2);
  sha256_update(&ctx, p3, l3);
  sha256_final(&ctx, out);
}

void h4_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg1, size_t msg1_len,
    const uint8_t *msg2, size_t msg2_len,
    uint8_t out[H4_SHA256_LEN]) {
  uint8_t kblock[64];
  memset(kblock, 0, sizeof(kblock));
  if (key_len > 64) {
    h4_sha256(key, key_len, kblock);
  } else if (key_len > 0 && key != NULL) {
    memcpy(kblock, key, key_len);
  }
  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) {
    ipad[i] = (uint8_t)(kblock[i] ^ 0x36u);
    opad[i] = (uint8_t)(kblock[i] ^ 0x5cu);
  }
  uint8_t inner[H4_SHA256_LEN];
  sha256_3parts(ipad, 64, msg1, msg1_len, msg2, msg2_len, inner);
  sha256_3parts(opad, 64, inner, H4_SHA256_LEN, NULL, 0, out);
}

int h4_has_leading_zero_bits(const uint8_t *buf, size_t len, uint32_t bits) {
  if (bits == 0) return 1;
  if (buf == NULL || bits > len * 8u) return 0;
  uint32_t have = 0;
  for (size_t i = 0; i < len; i++) {
    uint8_t b = buf[i];
    if (b == 0) {
      have += 8u;
      if (have >= bits) return 1;
      continue;
    }
    uint32_t z = 0;
    while ((b & 0x80u) == 0) {
      z++;
      b = (uint8_t)(b << 1);
    }
    have += z;
    return have >= bits ? 1 : 0;
  }
  return have >= bits ? 1 : 0;
}

int h4_poe_verify(const uint8_t *challenge, size_t chal_len, uint64_t nonce, uint32_t bits) {
  if (challenge == NULL && chal_len > 0) return 0;
  uint8_t nbuf[8];
  write_nonce_pair(nbuf, nonce);
  uint8_t digest[H4_SHA256_LEN];
  sha256_3parts(nbuf, 8, challenge, chal_len, NULL, 0, digest);
  return h4_has_leading_zero_bits(digest, H4_SHA256_LEN, bits);
}

int h4_poe_solve(
    const uint8_t *challenge, size_t chal_len,
    uint32_t bits, uint64_t max_iter,
    uint64_t *nonce_out, uint8_t hash_out[H4_SHA256_LEN]) {
  if ((challenge == NULL && chal_len > 0) || nonce_out == NULL || hash_out == NULL) return 0;
  if (bits > 256) return 0;

  uint8_t stack_buf[256];
  uint8_t *buf = stack_buf;
  size_t total = 8 + chal_len;
  if (total > sizeof(stack_buf)) {
    buf = (uint8_t *)malloc(total);
    if (buf == NULL) return 0;
  }
  if (chal_len > 0) memcpy(buf + 8, challenge, chal_len);

  int found = 0;
  for (uint64_t i = 0; i < max_iter; i++) {
    write_nonce_pair(buf, i);
    h4_sha256(buf, total, hash_out);
    if (h4_has_leading_zero_bits(hash_out, H4_SHA256_LEN, bits)) {
      *nonce_out = i;
      found = 1;
      break;
    }
  }

  if (buf != stack_buf) free(buf);
  return found;
}

/* ── 4 KB Memory-Hard L7 Puzzle ────────────────────────────────────────────── */

void h4_memhard_hash(
    const uint8_t *challenge, size_t chal_len,
    uint64_t nonce, uint8_t out[H4_SHA256_LEN]) {
  static const uint8_t TAG1[7] = { 'H', '4', '-', 'M', 'H', '1', '|' };
  static const uint8_t TAG2[7] = { 'H', '4', '-', 'M', 'H', '2', '|' };
  uint8_t nbuf[8];
  write_nonce_pair(nbuf, nonce);

  uint8_t seed[H4_SHA256_LEN];
  sha256_3parts(TAG1, sizeof(TAG1), nbuf, 8, challenge, chal_len, seed);

  uint32_t s[8];
  for (int i = 0; i < 8; i++) s[i] = read_u32_be(seed + i * 4);

  uint32_t pad[1024];
  uint32_t acc = s[0] ^ UINT32_C(0x9e3779b9);
  for (uint32_t i = 0; i < 1024u; i++) {
    uint32_t w = s[i & 7u] + i;
    uint32_t rot = (w << 13) | (w >> 19);
    acc ^= rot;
    acc = acc * UINT32_C(0x85ebca6b) + UINT32_C(0xc2b2ae35);
    pad[i] = acc ^ (acc >> 16);
  }

  uint32_t st = s[1] ^ pad[s[2] & 1023u];
  for (uint32_t r = 0; r < 64u; r++) {
    uint32_t idx = st & 1023u;
    uint32_t v = pad[idx];
    st = (st ^ v ^ r) * UINT32_C(0xcc9e2d51);
    st = ((st << 15) | (st >> 17)) * UINT32_C(0x1b873593);
    uint32_t dst = (idx + (st >> 22) + 1u) & 1023u;
    pad[dst] ^= st;
  }

  uint8_t mix_bytes[32];
  for (uint32_t k = 0; k < 8u; k++) {
    uint32_t f = pad[(st + k * 127u) & 1023u] ^ st;
    write_u32_be(mix_bytes + k * 4u, f);
  }

  /* Final hash over TAG2 || nonce8 || challenge || mix_bytes */
  uint8_t prefix[15];
  memcpy(prefix, TAG2, 7);
  memcpy(prefix + 7, nbuf, 8);
  sha256_3parts(prefix, 15, challenge, chal_len, mix_bytes, 32, out);
}

int h4_memhard_verify(const uint8_t *challenge, size_t chal_len, uint64_t nonce, uint32_t bits) {
  if (challenge == NULL && chal_len > 0) return 0;
  uint8_t digest[H4_SHA256_LEN];
  h4_memhard_hash(challenge, chal_len, nonce, digest);
  return h4_has_leading_zero_bits(digest, H4_SHA256_LEN, bits);
}

int h4_memhard_solve(
    const uint8_t *challenge, size_t chal_len,
    uint32_t bits, uint64_t max_iter,
    uint64_t *nonce_out, uint8_t hash_out[H4_SHA256_LEN]) {
  if ((challenge == NULL && chal_len > 0) || nonce_out == NULL || hash_out == NULL) return 0;
  if (bits > 256) return 0;
  for (uint64_t i = 0; i < max_iter; i++) {
    h4_memhard_hash(challenge, chal_len, i, hash_out);
    if (h4_has_leading_zero_bits(hash_out, H4_SHA256_LEN, bits)) {
      *nonce_out = i;
      return 1;
    }
  }
  return 0;
}

/* ── Capability HMAC Chain Verifier ────────────────────────────────────────── */

int h4_verify_cap_links(
    const uint8_t *sig0, size_t sig0_len,
    const uint8_t *domain, size_t domain_len,
    const uint8_t *packed_links, size_t packed_len,
    uint8_t tip_sig_out[H4_HMAC128_LEN],
    size_t *hops_out) {
  if (sig0 == NULL || sig0_len == 0 || tip_sig_out == NULL || hops_out == NULL) return -1;
  if (packed_len == 0) {
    *hops_out = 0;
    return 1;
  }
  if (packed_links == NULL) return -1;

  const uint8_t *prev_key = sig0;
  size_t prev_key_len = sig0_len;
  uint8_t cur_sig[H4_HMAC128_LEN];
  size_t off = 0;
  size_t hops = 0;

  while (off < packed_len) {
    uint64_t clen = 0;
    size_t vsz = h4_varint_decode(packed_links + off, packed_len - off, &clen);
    if (vsz == 0) return -1;
    off += vsz;
    if (clen > packed_len - off) return -1;
    const uint8_t *claims = packed_links + off;
    off += (size_t)clen;
    if (H4_HMAC128_LEN > packed_len - off) return -1;
    const uint8_t *got_link = packed_links + off;
    off += H4_HMAC128_LEN;

    uint8_t full_hmac[H4_SHA256_LEN];
    h4_hmac_sha256(prev_key, prev_key_len, domain, domain_len, claims, (size_t)clen, full_hmac);
    if (!h4_ct_equal(full_hmac, got_link, H4_HMAC128_LEN)) {
      *hops_out = hops;
      return 0;
    }
    memcpy(cur_sig, got_link, H4_HMAC128_LEN);
    prev_key = cur_sig;
    prev_key_len = H4_HMAC128_LEN;
    hops++;
    if (hops > 64) return -1;
  }

  memcpy(tip_sig_out, cur_sig, H4_HMAC128_LEN);
  *hops_out = hops;
  return 1;
}

/* ── Fast Frame Scanner ────────────────────────────────────────────────────── */

int h4_scan_frames(
    const uint8_t *buf, size_t len,
    uint64_t *out_triples, size_t max_frames) {
  if (len == 0) return 0;
  if (buf == NULL || out_triples == NULL) return -1;

  size_t off = 0;
  size_t count = 0;
  while (off < len) {
    if (count >= max_frames) return -1;
    uint64_t ftype = 0, flen = 0;
    size_t tsz = h4_varint_decode(buf + off, len - off, &ftype);
    if (tsz == 0 || ftype > UINT64_C(9007199254740991)) return -1;
    off += tsz;
    size_t lsz = h4_varint_decode(buf + off, len - off, &flen);
    if (lsz == 0 || flen > UINT64_C(9007199254740991)) return -1;
    off += lsz;
    if (flen > len - off) return -1;

    out_triples[count * 3] = ftype;
    out_triples[count * 3 + 1] = (uint64_t)off;
    out_triples[count * 3 + 2] = flen;
    off += (size_t)flen;
    count++;
  }
  return (int)count;
}
