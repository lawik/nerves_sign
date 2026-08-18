// SPDX-License-Identifier: Apache-2.0
//
// Published test vectors for the SHA-256 / HMAC / HKDF implementation.
//
// These matter more than most tests here. A derivation that is subtly wrong
// still produces 64 plausible hex characters, and nothing downstream can tell
// the difference — the device simply cannot decrypt itself, once, permanently,
// after the key has already been burned. Checking against FIPS 180-4,
// RFC 4231 and RFC 5869 is the only way to know the arithmetic is right.

#include "../kdf.h"

#include <stdio.h>
#include <string.h>

static int failures;
static const char *current_test;

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            fprintf(stderr, "  FAIL %s:%d: %s\n", current_test, __LINE__, #cond);         \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

static void to_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", in[i]);
}

static void fill(uint8_t *buf, size_t len, uint8_t value)
{
    memset(buf, value, len);
}

// ---- SHA-256, FIPS 180-4 ---------------------------------------------------

static void test_sha256_vectors(void)
{
    current_test = "sha256 vectors";

    uint8_t d[SHA256_DIGEST_LEN];
    char hex[SHA256_DIGEST_LEN * 2 + 1];

    sha256((const uint8_t *)"abc", 3, d);
    to_hex(d, sizeof(d), hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

    sha256((const uint8_t *)"", 0, d);
    to_hex(d, sizeof(d), hex);
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);

    // Two blocks, exercising the length padding across a boundary.
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256((const uint8_t *)msg, strlen(msg), d);
    to_hex(d, sizeof(d), hex);
    CHECK(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
}

static void test_sha256_block_boundaries(void)
{
    current_test = "sha256 at block boundaries";

    // 55, 56 and 64 bytes are where the padding logic changes: 56 forces an
    // extra block because the length no longer fits.
    uint8_t buf[64];
    uint8_t d[SHA256_DIGEST_LEN];
    char hex[SHA256_DIGEST_LEN * 2 + 1];

    fill(buf, 55, 'a');
    sha256(buf, 55, d);
    to_hex(d, sizeof(d), hex);
    CHECK(strcmp(hex, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318") == 0);

    fill(buf, 56, 'a');
    sha256(buf, 56, d);
    to_hex(d, sizeof(d), hex);
    CHECK(strcmp(hex, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a") == 0);

    fill(buf, 64, 'a');
    sha256(buf, 64, d);
    to_hex(d, sizeof(d), hex);
    CHECK(strcmp(hex, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb") == 0);
}

// ---- HMAC-SHA256, RFC 4231 -------------------------------------------------

static void test_hmac_vectors(void)
{
    current_test = "hmac-sha256 RFC 4231";

    uint8_t key[131];
    uint8_t mac[SHA256_DIGEST_LEN];
    char hex[SHA256_DIGEST_LEN * 2 + 1];

    // Case 1
    fill(key, 20, 0x0b);
    hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, mac);
    to_hex(mac, sizeof(mac), hex);
    CHECK(strcmp(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") == 0);

    // Case 2: key shorter than the block
    hmac_sha256((const uint8_t *)"Jefe", 4,
                (const uint8_t *)"what do ya want for nothing?", 28, mac);
    to_hex(mac, sizeof(mac), hex);
    CHECK(strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0);

    // Case 6: key longer than the block, so it gets hashed first
    fill(key, 131, 0xaa);
    hmac_sha256(key, 131,
                (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54,
                mac);
    to_hex(mac, sizeof(mac), hex);
    CHECK(strcmp(hex, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54") == 0);
}

// ---- HKDF, RFC 5869 --------------------------------------------------------

static void test_hkdf_case1(void)
{
    current_test = "hkdf RFC 5869 case 1";

    uint8_t ikm[22];
    const uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const uint8_t info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    uint8_t prk[SHA256_DIGEST_LEN];
    uint8_t okm[42];
    char hex[128];

    fill(ikm, sizeof(ikm), 0x0b);

    hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
    to_hex(prk, sizeof(prk), hex);
    CHECK(strcmp(hex, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5") == 0);

    CHECK(hkdf_expand(prk, info, sizeof(info), okm, sizeof(okm)) == 0);
    to_hex(okm, sizeof(okm), hex);
    CHECK(strcmp(hex, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                      "34007208d5b887185865") == 0);
}

static void test_hkdf_case3_empty_salt_and_info(void)
{
    current_test = "hkdf RFC 5869 case 3";

    // This is the shape the helper actually uses: no salt, only a purpose
    // string as info.
    uint8_t ikm[22];
    uint8_t prk[SHA256_DIGEST_LEN];
    uint8_t okm[42];
    char hex[128];

    fill(ikm, sizeof(ikm), 0x0b);

    hkdf_extract(NULL, 0, ikm, sizeof(ikm), prk);
    to_hex(prk, sizeof(prk), hex);
    CHECK(strcmp(hex, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04") == 0);

    CHECK(hkdf_expand(prk, (const uint8_t *)"", 0, okm, sizeof(okm)) == 0);
    to_hex(okm, sizeof(okm), hex);
    CHECK(strcmp(hex, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                      "9d201395faa4b61a96c8") == 0);
}

// ---- properties the helper depends on --------------------------------------

static void test_purposes_differ(void)
{
    current_test = "different purposes give different keys";

    uint8_t ikm[32];
    uint8_t a[32];
    uint8_t b[32];

    fill(ikm, sizeof(ikm), 0x42);

    CHECK(hkdf(NULL, 0, ikm, sizeof(ikm), (const uint8_t *)"rootfs", 6, a, sizeof(a)) == 0);
    CHECK(hkdf(NULL, 0, ikm, sizeof(ikm), (const uint8_t *)"data", 4, b, sizeof(b)) == 0);

    // The whole reason for a purpose string: one compromised volume key must
    // not be the other volume's key.
    CHECK(memcmp(a, b, sizeof(a)) != 0);
}

static void test_deterministic(void)
{
    current_test = "derivation is deterministic";

    uint8_t ikm[32];
    uint8_t a[32];
    uint8_t b[32];

    fill(ikm, sizeof(ikm), 0x42);

    CHECK(hkdf(NULL, 0, ikm, sizeof(ikm), (const uint8_t *)"rootfs", 6, a, sizeof(a)) == 0);
    CHECK(hkdf(NULL, 0, ikm, sizeof(ikm), (const uint8_t *)"rootfs", 6, b, sizeof(b)) == 0);

    // Every boot must derive the same key from the same fuse, forever.
    CHECK(memcmp(a, b, sizeof(a)) == 0);
}

static void test_ikm_changes_key(void)
{
    current_test = "a different device key gives a different result";

    uint8_t ikm1[32];
    uint8_t ikm2[32];
    uint8_t a[32];
    uint8_t b[32];

    fill(ikm1, sizeof(ikm1), 0x42);
    fill(ikm2, sizeof(ikm2), 0x43);

    CHECK(hkdf(NULL, 0, ikm1, sizeof(ikm1), (const uint8_t *)"rootfs", 6, a, sizeof(a)) == 0);
    CHECK(hkdf(NULL, 0, ikm2, sizeof(ikm2), (const uint8_t *)"rootfs", 6, b, sizeof(b)) == 0);

    CHECK(memcmp(a, b, sizeof(a)) != 0);
}

static void test_expand_length_limit(void)
{
    current_test = "expand refuses more than 255 blocks";

    uint8_t prk[SHA256_DIGEST_LEN];
    static uint8_t big[255 * SHA256_DIGEST_LEN + 1];

    fill(prk, sizeof(prk), 0x11);

    CHECK(hkdf_expand(prk, (const uint8_t *)"x", 1, big, sizeof(big)) == -1);
    CHECK(hkdf_expand(prk, (const uint8_t *)"x", 1, big, 255 * SHA256_DIGEST_LEN) == 0);
}

int main(void)
{
    test_sha256_vectors();
    test_sha256_block_boundaries();
    test_hmac_vectors();
    test_hkdf_case1();
    test_hkdf_case3_empty_salt_and_info();
    test_purposes_differ();
    test_deterministic();
    test_ikm_changes_key();
    test_expand_length_limit();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("kdf: all checks passed\n");
    return 0;
}
