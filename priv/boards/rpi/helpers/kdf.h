// SPDX-License-Identifier: Apache-2.0
//
// SHA-256, HMAC-SHA256 and HKDF (RFC 5869), self-contained.
//
// Static musl has no crypto library and the initramfs has nothing else in it,
// so this is written out rather than linked. It is small, it is only ever fed
// key material we already hold, and every function is checked against the
// published test vectors in tests/kdf_test.c — which matters more than usual,
// because a derivation that is subtly wrong still produces 64 plausible hex
// characters and only fails once a device cannot decrypt itself.

#ifndef KDF_H
#define KDF_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32
#define SHA256_BLOCK_LEN 64

void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                 uint8_t out[SHA256_DIGEST_LEN]);

// HKDF-Extract: salt may be NULL/0, in which case a block of zeros is used.
void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                  uint8_t prk[SHA256_DIGEST_LEN]);

// HKDF-Expand. `out_len` must be <= 255 * 32. Returns 0 on success, -1 if not.
int hkdf_expand(const uint8_t prk[SHA256_DIGEST_LEN], const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len);

// Extract-then-expand in one call.
int hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
         const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

#endif
