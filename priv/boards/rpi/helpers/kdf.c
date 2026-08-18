// SPDX-License-Identifier: Apache-2.0

#include "kdf.h"

#include <string.h>

// ---- SHA-256 (FIPS 180-4) --------------------------------------------------

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define BSIG1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SSIG0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))

struct sha256_ctx {
    uint32_t h[8];
    uint64_t bits;
    uint8_t buf[SHA256_BLOCK_LEN];
    size_t buf_len;
};

static void sha256_compress(struct sha256_ctx *c, const uint8_t *block)
{
    uint32_t w[64];

    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];

    for (int i = 16; i < 64; i++)
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, cc);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }

    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;

    memset(w, 0, sizeof(w));
}

static void sha256_init(struct sha256_ctx *c)
{
    c->h[0] = 0x6a09e667;
    c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372;
    c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f;
    c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab;
    c->h[7] = 0x5be0cd19;
    c->bits = 0;
    c->buf_len = 0;
}

static void sha256_update(struct sha256_ctx *c, const uint8_t *data, size_t len)
{
    c->bits += (uint64_t)len * 8;

    while (len > 0) {
        size_t take = SHA256_BLOCK_LEN - c->buf_len;
        if (take > len)
            take = len;

        memcpy(c->buf + c->buf_len, data, take);
        c->buf_len += take;
        data += take;
        len -= take;

        if (c->buf_len == SHA256_BLOCK_LEN) {
            sha256_compress(c, c->buf);
            c->buf_len = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN])
{
    uint64_t bits = c->bits;
    uint8_t pad = 0x80;

    sha256_update(c, &pad, 1);

    pad = 0x00;
    while (c->buf_len != 56)
        sha256_update(c, &pad, 1);

    // The length is appended as a big-endian 64-bit bit count, and must not go
    // through sha256_update or it would count itself.
    for (int i = 7; i >= 0; i--)
        c->buf[c->buf_len++] = (uint8_t)(bits >> (i * 8));

    sha256_compress(c, c->buf);

    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)c->h[i];
    }

    memset(c, 0, sizeof(*c));
}

void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LEN])
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

// ---- HMAC-SHA256 (RFC 2104) ------------------------------------------------

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                 uint8_t out[SHA256_DIGEST_LEN])
{
    uint8_t k[SHA256_BLOCK_LEN];
    uint8_t pad[SHA256_BLOCK_LEN];
    uint8_t inner[SHA256_DIGEST_LEN];
    struct sha256_ctx c;

    memset(k, 0, sizeof(k));

    if (key_len > SHA256_BLOCK_LEN)
        sha256(key, key_len, k);
    else
        memcpy(k, key, key_len);

    for (size_t i = 0; i < SHA256_BLOCK_LEN; i++)
        pad[i] = k[i] ^ 0x36;

    sha256_init(&c);
    sha256_update(&c, pad, sizeof(pad));
    sha256_update(&c, data, data_len);
    sha256_final(&c, inner);

    for (size_t i = 0; i < SHA256_BLOCK_LEN; i++)
        pad[i] = k[i] ^ 0x5c;

    sha256_init(&c);
    sha256_update(&c, pad, sizeof(pad));
    sha256_update(&c, inner, sizeof(inner));
    sha256_final(&c, out);

    // Key-derived material must not be left on the stack for the rest of the
    // boot; this program's whole job is handling a secret.
    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
    memset(inner, 0, sizeof(inner));
}

// ---- HKDF (RFC 5869) -------------------------------------------------------

void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                  uint8_t prk[SHA256_DIGEST_LEN])
{
    static const uint8_t zeros[SHA256_DIGEST_LEN] = {0};

    if (!salt || salt_len == 0) {
        salt = zeros;
        salt_len = sizeof(zeros);
    }

    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int hkdf_expand(const uint8_t prk[SHA256_DIGEST_LEN], const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len)
{
    if (out_len > 255 * SHA256_DIGEST_LEN)
        return -1;

    uint8_t t[SHA256_DIGEST_LEN];
    size_t t_len = 0;
    size_t done = 0;
    uint8_t counter = 1;

    while (done < out_len) {
        uint8_t block[SHA256_BLOCK_LEN + 256 + 1];
        size_t n = 0;

        // T(i) = HMAC(PRK, T(i-1) | info | i)
        memcpy(block + n, t, t_len);
        n += t_len;

        if (info_len > 256)
            return -1;

        memcpy(block + n, info, info_len);
        n += info_len;
        block[n++] = counter;

        hmac_sha256(prk, SHA256_DIGEST_LEN, block, n, t);
        t_len = SHA256_DIGEST_LEN;

        size_t take = out_len - done;
        if (take > SHA256_DIGEST_LEN)
            take = SHA256_DIGEST_LEN;

        memcpy(out + done, t, take);
        done += take;
        counter++;

        memset(block, 0, sizeof(block));
    }

    memset(t, 0, sizeof(t));
    return 0;
}

int hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
         const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
    uint8_t prk[SHA256_DIGEST_LEN];

    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    int rc = hkdf_expand(prk, info, info_len, out, out_len);

    memset(prk, 0, sizeof(prk));
    return rc;
}
