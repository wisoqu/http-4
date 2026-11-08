#ifndef H4_CORE_H
#define H4_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define H4_MAX_VARINT UINT64_C(0x3fffffffffffffff)
#define H4_SHA256_LEN 32
#define H4_HMAC128_LEN 16

/* Constant-time comparison: returns 1 if equal, 0 otherwise. */
int h4_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* QUIC-compatible varint (RFC 9000 §16). Returns bytes written/read (1,2,4,8), or 0 on error. */
size_t h4_varint_encode(uint8_t *out, size_t out_cap, uint64_t val);
size_t h4_varint_decode(const uint8_t *in, size_t in_len, uint64_t *val_out);

/* 62-bit safe ZigZag encoding/decoding. Returns 1 on ok, 0 on overflow. */
int h4_zigzag_encode(int64_t n, uint64_t *out);
int64_t h4_zigzag_decode(uint64_t u);

/* SHA-256 and HMAC-SHA256 primitives. */
void h4_sha256(const uint8_t *data, size_t len, uint8_t out[H4_SHA256_LEN]);
void h4_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg1, size_t msg1_len,
    const uint8_t *msg2, size_t msg2_len,
    uint8_t out[H4_SHA256_LEN]);

/* Count leading zero bits: returns 1 if hash has >= bits leading zeros. */
int h4_has_leading_zero_bits(const uint8_t *buf, size_t len, uint32_t bits);

/* SHA-256 Proof-of-Effort solve & verify. Returns 1 if solved/valid, 0 otherwise. */
int h4_poe_verify(const uint8_t *challenge, size_t chal_len, uint64_t nonce, uint32_t bits);
int h4_poe_solve(
    const uint8_t *challenge, size_t chal_len,
    uint32_t bits, uint64_t max_iter,
    uint64_t *nonce_out, uint8_t hash_out[H4_SHA256_LEN]);

/* 4 KB Cache/Memory-Hard L7 Puzzle (GPU-hostile, O(1) ~2.5us verify). */
void h4_memhard_hash(
    const uint8_t *challenge, size_t chal_len,
    uint64_t nonce, uint8_t out[H4_SHA256_LEN]);
int h4_memhard_verify(const uint8_t *challenge, size_t chal_len, uint64_t nonce, uint32_t bits);
int h4_memhard_solve(
    const uint8_t *challenge, size_t chal_len,
    uint32_t bits, uint64_t max_iter,
    uint64_t *nonce_out, uint8_t hash_out[H4_SHA256_LEN]);

/* Verify a flat array of capability attenuation links in one C pass.
 * `packed_links` format: repeated [varint(claims_len) | claims | 16B_link].
 * Returns 1 if all HMAC128 links match, 0 on mismatch, -1 on malformed input. */
int h4_verify_cap_links(
    const uint8_t *sig0, size_t sig0_len,
    const uint8_t *domain, size_t domain_len,
    const uint8_t *packed_links, size_t packed_len,
    uint8_t tip_sig_out[H4_HMAC128_LEN],
    size_t *hops_out);

/* Validate and index frames in `buf`.
 * Writes triples [type, payload_offset, payload_length] into `out_triples` (cap = max_frames * 3).
 * Returns number of frames (>= 0), or -1 on truncated/malformed frame. */
int h4_scan_frames(
    const uint8_t *buf, size_t len,
    uint64_t *out_triples, size_t max_frames);

#ifdef __cplusplus
}
#endif

#endif /* H4_CORE_H */
