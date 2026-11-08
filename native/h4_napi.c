#define NAPI_VERSION 8
#include <node_api.h>
#include <string.h>
#include "h4_core.h"

#define NAPI_CHECK(env, expr)                                            \
  do {                                                                   \
    if ((expr) != napi_ok) {                                             \
      napi_throw_error((env), NULL, "N-API failure: " #expr);            \
      return NULL;                                                       \
    }                                                                    \
  } while (0)

static int get_bytes(napi_env env, napi_value val, const uint8_t **ptr, size_t *len) {
  bool is_buf = false;
  if (napi_is_buffer(env, val, &is_buf) == napi_ok && is_buf) {
    void *data = NULL;
    if (napi_get_buffer_info(env, val, &data, len) != napi_ok) return 0;
    *ptr = (const uint8_t *)data;
    return 1;
  }
  bool is_ta = false;
  if (napi_is_typedarray(env, val, &is_ta) == napi_ok && is_ta) {
    napi_typedarray_type type;
    void *data = NULL;
    napi_value ab;
    size_t byte_offset = 0;
    if (napi_get_typedarray_info(env, val, &type, len, &data, &ab, &byte_offset) != napi_ok) return 0;
    size_t elem = 1;
    if (type == napi_uint16_array || type == napi_int16_array) elem = 2;
    else if (type == napi_uint32_array || type == napi_int32_array || type == napi_float32_array) elem = 4;
    else if (type == napi_float64_array || type == napi_bigint64_array || type == napi_biguint64_array) elem = 8;
    *len *= elem;
    *ptr = (const uint8_t *)data;
    return 1;
  }
  return 0;
}

/* solvePoE(challengeBuf, bits, maxIter) -> { nonce, hash } | null */
static napi_value napi_solve_poe(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  if (argc < 3) {
    napi_throw_type_error(env, NULL, "solvePoE expects (challenge, bits, maxIter)");
    return NULL;
  }
  const uint8_t *chal = NULL;
  size_t chal_len = 0;
  if (!get_bytes(env, argv[0], &chal, &chal_len)) {
    napi_throw_type_error(env, NULL, "challenge must be Buffer/Uint8Array");
    return NULL;
  }
  uint32_t bits = 0;
  double max_iter_d = 0;
  NAPI_CHECK(env, napi_get_value_uint32(env, argv[1], &bits));
  NAPI_CHECK(env, napi_get_value_double(env, argv[2], &max_iter_d));
  uint64_t max_iter = max_iter_d > 0 ? (uint64_t)max_iter_d : 0;

  uint64_t nonce = 0;
  uint8_t hash[H4_SHA256_LEN];
  if (!h4_poe_solve(chal, chal_len, bits, max_iter, &nonce, hash)) {
    napi_value null_val;
    NAPI_CHECK(env, napi_get_null(env, &null_val));
    return null_val;
  }

  napi_value out_obj, nonce_val, hash_buf;
  void *hash_dst = NULL;
  NAPI_CHECK(env, napi_create_object(env, &out_obj));
  NAPI_CHECK(env, napi_create_double(env, (double)nonce, &nonce_val));
  NAPI_CHECK(env, napi_create_buffer_copy(env, H4_SHA256_LEN, hash, &hash_dst, &hash_buf));
  NAPI_CHECK(env, napi_set_named_property(env, out_obj, "nonce", nonce_val));
  NAPI_CHECK(env, napi_set_named_property(env, out_obj, "hash", hash_buf));
  return out_obj;
}

/* checkPoE(challengeBuf, nonce, bits) -> boolean */
static napi_value napi_check_poe(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  const uint8_t *chal = NULL;
  size_t chal_len = 0;
  if (argc < 3 || !get_bytes(env, argv[0], &chal, &chal_len)) {
    napi_value f;
    NAPI_CHECK(env, napi_get_boolean(env, false, &f));
    return f;
  }
  double nonce_d = -1;
  uint32_t bits = 0;
  NAPI_CHECK(env, napi_get_value_double(env, argv[1], &nonce_d));
  NAPI_CHECK(env, napi_get_value_uint32(env, argv[2], &bits));
  if (nonce_d < 0 || nonce_d > 9007199254740991.0) {
    napi_value f;
    NAPI_CHECK(env, napi_get_boolean(env, false, &f));
    return f;
  }
  int ok = h4_poe_verify(chal, chal_len, (uint64_t)nonce_d, bits);
  napi_value res;
  NAPI_CHECK(env, napi_get_boolean(env, ok != 0, &res));
  return res;
}

/* memHardHash(challengeBuf, nonce) -> Buffer(32) */
static napi_value napi_memhard_hash(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  const uint8_t *chal = NULL;
  size_t chal_len = 0;
  if (argc < 2 || !get_bytes(env, argv[0], &chal, &chal_len)) {
    napi_throw_type_error(env, NULL, "memHardHash expects (Buffer, nonce)");
    return NULL;
  }
  double nonce_d = 0;
  NAPI_CHECK(env, napi_get_value_double(env, argv[1], &nonce_d));
  uint8_t digest[H4_SHA256_LEN];
  h4_memhard_hash(chal, chal_len, (uint64_t)(nonce_d > 0 ? nonce_d : 0), digest);
  napi_value out;
  void *dst = NULL;
  NAPI_CHECK(env, napi_create_buffer_copy(env, H4_SHA256_LEN, digest, &dst, &out));
  return out;
}

/* solveMemHard(challengeBuf, bits, maxIter) -> { nonce, hash } | null */
static napi_value napi_solve_memhard(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  const uint8_t *chal = NULL;
  size_t chal_len = 0;
  if (argc < 3 || !get_bytes(env, argv[0], &chal, &chal_len)) {
    napi_throw_type_error(env, NULL, "solveMemHard expects (challenge, bits, maxIter)");
    return NULL;
  }
  uint32_t bits = 0;
  double max_iter_d = 0;
  NAPI_CHECK(env, napi_get_value_uint32(env, argv[1], &bits));
  NAPI_CHECK(env, napi_get_value_double(env, argv[2], &max_iter_d));
  uint64_t nonce = 0;
  uint8_t hash[H4_SHA256_LEN];
  if (!h4_memhard_solve(chal, chal_len, bits, max_iter_d > 0 ? (uint64_t)max_iter_d : 0, &nonce, hash)) {
    napi_value null_val;
    NAPI_CHECK(env, napi_get_null(env, &null_val));
    return null_val;
  }
  napi_value out_obj, nonce_val, hash_buf;
  void *dst = NULL;
  NAPI_CHECK(env, napi_create_object(env, &out_obj));
  NAPI_CHECK(env, napi_create_double(env, (double)nonce, &nonce_val));
  NAPI_CHECK(env, napi_create_buffer_copy(env, H4_SHA256_LEN, hash, &dst, &hash_buf));
  NAPI_CHECK(env, napi_set_named_property(env, out_obj, "nonce", nonce_val));
  NAPI_CHECK(env, napi_set_named_property(env, out_obj, "hash", hash_buf));
  return out_obj;
}

/* checkMemHard(challengeBuf, nonce, bits) -> boolean */
static napi_value napi_check_memhard(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  const uint8_t *chal = NULL;
  size_t chal_len = 0;
  if (argc < 3 || !get_bytes(env, argv[0], &chal, &chal_len)) {
    napi_value f;
    NAPI_CHECK(env, napi_get_boolean(env, false, &f));
    return f;
  }
  double nonce_d = -1;
  uint32_t bits = 0;
  NAPI_CHECK(env, napi_get_value_double(env, argv[1], &nonce_d));
  NAPI_CHECK(env, napi_get_value_uint32(env, argv[2], &bits));
  if (nonce_d < 0 || nonce_d > 9007199254740991.0) {
    napi_value f;
    NAPI_CHECK(env, napi_get_boolean(env, false, &f));
    return f;
  }
  int ok = h4_memhard_verify(chal, chal_len, (uint64_t)nonce_d, bits);
  napi_value res;
  NAPI_CHECK(env, napi_get_boolean(env, ok != 0, &res));
  return res;
}

/* hmacSha256(keyBuf, domainBuf, msgBuf, outLen) -> Buffer(outLen) */
static napi_value napi_hmac_sha256(napi_env env, napi_callback_info info) {
  size_t argc = 4;
  napi_value argv[4];
  NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  const uint8_t *key = NULL, *dom = NULL, *msg = NULL;
  size_t key_len = 0, dom_len = 0, msg_len = 0;
  uint32_t out_len = H4_SHA256_LEN;
  if (argc < 4 || !get_bytes(env, argv[0], &key, &key_len) ||
      !get_bytes(env, argv[1], &dom, &dom_len) ||
      !get_bytes(env, argv[2], &msg, &msg_len)) {
    napi_throw_type_error(env, NULL, "hmacSha256 expects (key, domain, msg, outLen)");
    return NULL;
  }
  NAPI_CHECK(env, napi_get_value_uint32(env, argv[3], &out_len));
  if (out_len == 0 || out_len > H4_SHA256_LEN) out_len = H4_SHA256_LEN;

  uint8_t digest[H4_SHA256_LEN];
  h4_hmac_sha256(key, key_len, dom, dom_len, msg, msg_len, digest);
  napi_value out;
  void *dst = NULL;
  NAPI_CHECK(env, napi_create_buffer_copy(env, out_len, digest, &dst, &out));
  return out;
}

/* verifyCapLinks(sig0Buf, domainBuf, packedLinksBuf) -> { ok, hops, tip? } */
static napi_value napi_verify_cap_links(napi_env env, napi_callback_info info) {
  size_t argc = 3;
  napi_value argv[3];
  NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  const uint8_t *sig0 = NULL, *dom = NULL, *packed = NULL;
  size_t sig0_len = 0, dom_len = 0, packed_len = 0;
  if (argc < 3 || !get_bytes(env, argv[0], &sig0, &sig0_len) ||
      !get_bytes(env, argv[1], &dom, &dom_len) ||
      !get_bytes(env, argv[2], &packed, &packed_len)) {
    napi_throw_type_error(env, NULL, "verifyCapLinks expects (sig0, domain, packedLinks)");
    return NULL;
  }

  uint8_t tip[H4_HMAC128_LEN];
  size_t hops = 0;
  int rc = h4_verify_cap_links(sig0, sig0_len, dom, dom_len, packed, packed_len, tip, &hops);

  napi_value out_obj, rc_val, hops_val;
  NAPI_CHECK(env, napi_create_object(env, &out_obj));
  NAPI_CHECK(env, napi_create_int32(env, rc, &rc_val));
  NAPI_CHECK(env, napi_create_uint32(env, (uint32_t)hops, &hops_val));
  NAPI_CHECK(env, napi_set_named_property(env, out_obj, "rc", rc_val));
  NAPI_CHECK(env, napi_set_named_property(env, out_obj, "hops", hops_val));
  if (rc == 1 && hops > 0) {
    napi_value tip_buf;
    void *dst = NULL;
    NAPI_CHECK(env, napi_create_buffer_copy(env, H4_HMAC128_LEN, tip, &dst, &tip_buf));
    NAPI_CHECK(env, napi_set_named_property(env, out_obj, "tip", tip_buf));
  }
  return out_obj;
}

/* scanFrames(buf) -> Float64Array [type0, off0, len0, ...] | null */
static napi_value napi_scan_frames(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value argv[1];
  NAPI_CHECK(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
  const uint8_t *buf = NULL;
  size_t len = 0;
  if (argc < 1 || !get_bytes(env, argv[0], &buf, &len)) {
    napi_throw_type_error(env, NULL, "scanFrames expects Buffer");
    return NULL;
  }
  uint64_t stack_triples[64 * 3];
  int n = h4_scan_frames(buf, len, stack_triples, 64);
  if (n < 0) {
    napi_value null_val;
    NAPI_CHECK(env, napi_get_null(env, &null_val));
    return null_val;
  }
  napi_value ab, ta;
  void *data = NULL;
  size_t count = (size_t)n * 3;
  NAPI_CHECK(env, napi_create_arraybuffer(env, count * sizeof(double), &data, &ab));
  double *out = (double *)data;
  for (size_t i = 0; i < count; i++) out[i] = (double)stack_triples[i];
  NAPI_CHECK(env, napi_create_typedarray(env, napi_float64_array, count, ab, 0, &ta));
  return ta;
}

static napi_value Init(napi_env env, napi_value exports) {
  napi_property_descriptor props[] = {
    { "solvePoE", NULL, napi_solve_poe, NULL, NULL, NULL, napi_default, NULL },
    { "checkPoE", NULL, napi_check_poe, NULL, NULL, NULL, napi_default, NULL },
    { "memHardHash", NULL, napi_memhard_hash, NULL, NULL, NULL, napi_default, NULL },
    { "solveMemHard", NULL, napi_solve_memhard, NULL, NULL, NULL, napi_default, NULL },
    { "checkMemHard", NULL, napi_check_memhard, NULL, NULL, NULL, napi_default, NULL },
    { "hmacSha256", NULL, napi_hmac_sha256, NULL, NULL, NULL, napi_default, NULL },
    { "verifyCapLinks", NULL, napi_verify_cap_links, NULL, NULL, NULL, napi_default, NULL },
    { "scanFrames", NULL, napi_scan_frames, NULL, NULL, NULL, napi_default, NULL },
  };
  NAPI_CHECK(env, napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]), props));
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
