// SPDX-License-Identifier: Apache-2.0

#include "otp.h"

#include "mailbox.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>

// Mailbox property tags for the device private key rows.
//
// Not the customer OTP tags (0x…21). Those rows are dumpable with
// `vcgencmd otp_dump`, which is the wrong place for a key that protects an
// encrypted rootfs. This is the area `rpi-otp-private-key` writes, and the
// area the tooling that has actually burned keys uses.
#define TAG_GET_PRIVATE_KEY 0x00030081u
#define TAG_SET_PRIVATE_KEY 0x00038081u

// Property buffer layout (all u32, native endian):
//   [0] total byte size
//   [1] request/response code
//   [2] tag id
//   [3] value buffer size in bytes
//   [4] tag request/response code
//   [5] first row index
//   [6] row count
//   [7..] row values
//   [..] end tag (0)
#define MSG_WORDS (7 + OTP_ROW_COUNT + 1)
#define MSG_ROWS_AT 7

#define MBOX_RESPONSE_OK 0x80000000u

static int transact(uint32_t tag, const uint32_t *in, uint32_t *out)
{
    uint32_t msg[MSG_WORDS];
    unsigned i = 0;

    msg[i++] = sizeof(msg);
    msg[i++] = 0;
    msg[i++] = tag;
    msg[i++] = (2 + OTP_ROW_COUNT) * (uint32_t)sizeof(uint32_t);
    msg[i++] = 0;
    msg[i++] = OTP_FIRST_ROW;
    msg[i++] = OTP_ROW_COUNT;
    for (unsigned r = 0; r < OTP_ROW_COUNT; r++)
        msg[i++] = in ? in[r] : 0;
    msg[i++] = 0;

    if (mailbox_property(msg) < 0)
        return -1;

    if (msg[1] != MBOX_RESPONSE_OK) {
        fprintf(stderr, "otp: mailbox returned error code 0x%08x\n", msg[1]);
        errno = EIO;
        return -1;
    }

    if (out)
        memcpy(out, &msg[MSG_ROWS_AT], OTP_ROW_COUNT * sizeof(uint32_t));

    return 0;
}

int otp_read(uint32_t rows[OTP_ROW_COUNT])
{
    return transact(TAG_GET_PRIVATE_KEY, NULL, rows);
}

int otp_blank(const uint32_t rows[OTP_ROW_COUNT])
{
    for (unsigned r = 0; r < OTP_ROW_COUNT; r++)
        if (rows[r] != 0)
            return 0;

    return 1;
}

int otp_write(const uint32_t rows[OTP_ROW_COUNT])
{
    uint32_t current[OTP_ROW_COUNT];

    // OTP bits only ever go 0 -> 1. Writing over a programmed row cannot be
    // undone and leaves a device whose rootfs can never be decrypted again, so
    // this refuses rather than trusting the caller to have checked.
    if (otp_read(current) < 0)
        return -1;

    if (!otp_blank(current)) {
        fprintf(stderr, "otp: refusing to write, the private key rows are already programmed\n");
        errno = EEXIST;
        return -1;
    }

    if (otp_blank(rows)) {
        fprintf(stderr, "otp: refusing to write an all-zero key\n");
        errno = EINVAL;
        return -1;
    }

    if (transact(TAG_SET_PRIVATE_KEY, rows, NULL) < 0)
        return -1;

    // A burn that silently did nothing would leave the caller encrypting with
    // a key the device cannot produce again after a reboot.
    if (otp_read(current) < 0)
        return -1;

    if (memcmp(current, rows, sizeof(current)) != 0) {
        fprintf(stderr, "otp: readback does not match what was written\n");
        errno = EIO;
        return -1;
    }

    return 0;
}

int otp_generate(uint32_t rows[OTP_ROW_COUNT])
{
    unsigned char buf[OTP_ROW_COUNT * sizeof(uint32_t)];
    size_t got = 0;

    // No fallback to a weaker source: a predictable key here is a device whose
    // rootfs anyone can decrypt, and failing loudly is the only safe outcome.
    while (got < sizeof(buf)) {
        ssize_t n = getrandom(buf + got, sizeof(buf) - got, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        got += (size_t)n;
    }

    // Big-endian per row so the hex string reads in the same byte order the
    // mailbox and rpi-otp-key present, keeping keys comparable across tools.
    for (unsigned r = 0; r < OTP_ROW_COUNT; r++) {
        const unsigned char *b = &buf[r * 4];
        rows[r] = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                  ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    }

    return 0;
}

void otp_format_hex(const uint32_t rows[OTP_ROW_COUNT], char *out)
{
    for (unsigned r = 0; r < OTP_ROW_COUNT; r++)
        sprintf(out + r * 8, "%08x", rows[r]);

    out[OTP_HEX_LEN] = '\0';
}
