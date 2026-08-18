// SPDX-License-Identifier: Apache-2.0
//
// Host tests for the OTP module, run against fake_mailbox.c. What is worth
// pinning here is the refusal logic: these rows are one-time programmable, so
// a wrong write bricks the device's ability to ever decrypt its own rootfs.
//
// The rows in question are the device private key area (mailbox tags 0x…81),
// not the customer OTP rows (0x…21). Customer OTP is readable with
// `vcgencmd otp_dump`, which is no place for the key protecting an encrypted
// rootfs.

#include "../otp.h"
#include "fake_mailbox.h"

#include <errno.h>
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

#define TEST(name)                                                                       \
    current_test = name;                                                                 \
    fake_mailbox_reset();

static const uint32_t A_KEY[OTP_ROW_COUNT] = {0xdeadbeef, 0x01234567, 2, 3, 4, 5, 6, 7};

static void test_read_roundtrip(void)
{
    TEST("read returns what the mailbox holds");

    fake_mailbox_set_rows(A_KEY);

    uint32_t rows[OTP_ROW_COUNT];
    CHECK(otp_read(rows) == 0);
    CHECK(memcmp(rows, A_KEY, sizeof(rows)) == 0);
}

static void test_blank_detection(void)
{
    TEST("blank is all rows zero");

    uint32_t rows[OTP_ROW_COUNT];
    CHECK(otp_read(rows) == 0);
    CHECK(otp_blank(rows) == 1);

    // A single set bit anywhere means provisioned. Treating a mostly-zero key
    // as blank would invite a second burn over a real one.
    rows[OTP_ROW_COUNT - 1] = 1;
    CHECK(otp_blank(rows) == 0);
}

static void test_write_then_read(void)
{
    TEST("write burns the key and reads it back");

    CHECK(otp_write(A_KEY) == 0);

    uint32_t rows[OTP_ROW_COUNT];
    CHECK(otp_read(rows) == 0);
    CHECK(memcmp(rows, A_KEY, sizeof(rows)) == 0);
}

static void test_write_refuses_when_programmed(void)
{
    TEST("write refuses a device that already has a key");

    fake_mailbox_set_rows(A_KEY);

    const uint32_t other[OTP_ROW_COUNT] = {9, 9, 9, 9, 9, 9, 9, 9};
    errno = 0;
    CHECK(otp_write(other) == -1);
    CHECK(errno == EEXIST);

    // Nothing was sent to the mailbox: OTP bits only go 0 -> 1, so a second
    // burn would OR into the existing key and destroy it permanently.
    CHECK(fake_mailbox_writes == 0);

    uint32_t rows[OTP_ROW_COUNT];
    fake_mailbox_get_rows(rows);
    CHECK(memcmp(rows, A_KEY, sizeof(rows)) == 0);
}

static void test_write_refuses_all_zero(void)
{
    TEST("write refuses an all-zero key");

    const uint32_t zero[OTP_ROW_COUNT] = {0};
    errno = 0;
    CHECK(otp_write(zero) == -1);
    CHECK(errno == EINVAL);
    CHECK(fake_mailbox_writes == 0);
}

static void test_write_detects_bad_readback(void)
{
    TEST("write fails when the readback does not match");

    // The burn silently does nothing. Without the readback check the caller
    // would encrypt with a key the device cannot produce after a reboot.
    fake_mailbox_fail_next(0);
    errno = 0;
    CHECK(otp_write(A_KEY) == -1);
}

static void test_generate(void)
{
    TEST("generate produces distinct non-blank keys");

    uint32_t a[OTP_ROW_COUNT];
    uint32_t b[OTP_ROW_COUNT];

    CHECK(otp_generate(a) == 0);
    CHECK(otp_generate(b) == 0);
    CHECK(otp_blank(a) == 0);
    CHECK(memcmp(a, b, sizeof(a)) != 0);
}

static void test_format_hex(void)
{
    TEST("hex is lowercase, zero padded, 64 chars");

    char out[OTP_HEX_LEN + 1];
    otp_format_hex(A_KEY, out);

    CHECK(strlen(out) == OTP_HEX_LEN);
    CHECK(strncmp(out, "deadbeef01234567", 16) == 0);
    // Row 2 is 2: it must pad to 8 characters or the key shifts.
    CHECK(strncmp(out + 16, "00000002", 8) == 0);
}

static void test_generated_key_survives_a_burn(void)
{
    TEST("a generated key round-trips through OTP");

    uint32_t key[OTP_ROW_COUNT];
    CHECK(otp_generate(key) == 0);
    CHECK(otp_write(key) == 0);

    uint32_t rows[OTP_ROW_COUNT];
    CHECK(otp_read(rows) == 0);
    CHECK(memcmp(rows, key, sizeof(rows)) == 0);

    char a[OTP_HEX_LEN + 1];
    char b[OTP_HEX_LEN + 1];
    otp_format_hex(key, a);
    otp_format_hex(rows, b);
    CHECK(strcmp(a, b) == 0);
}

static void test_mailbox_error_surfaces(void)
{
    TEST("a mailbox error code is a failure, not a zero key");

    fake_mailbox_fail_next(0x80000001u);

    uint32_t rows[OTP_ROW_COUNT];
    CHECK(otp_read(rows) == -1);
}

int main(void)
{
    test_read_roundtrip();
    test_blank_detection();
    test_write_then_read();
    test_write_refuses_when_programmed();
    test_write_refuses_all_zero();
    test_write_detects_bad_readback();
    test_generate();
    test_format_hex();
    test_generated_key_survives_a_burn();
    test_mailbox_error_surfaces();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("otp: all checks passed\n");
    return 0;
}
