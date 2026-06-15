// SPDX-License-Identifier: Apache-2.0
//
// nerves_sign default key helper for Raspberry Pi 4 / CM4 (and other Pi
// boards that expose customer OTP via the VideoCore mailbox).
//
// Reads the customer-programmable OTP rows through /dev/vcio and prints the
// key as lowercase hex on stdout, which is the contract nerves_cryptinit's
// `cmd:` key source expects (64 hex chars for a 256-bit key, exit 0).
//
// Build static against the musl Nerves toolchain, install at /usr/sbin/unlock,
// and reference it from initramfs.conf:
//
//     rootfs_key = cmd:/usr/sbin/unlock
//
// This is the *default* helper. Projects can point nerves_sign at an alternate
// source via `config :nerves_sign, key_helper_source: "path/to/your.c"` (for
// example to add HKDF per-partition key derivation, or a first-boot bootstrap
// state machine). See helpers/README.md.
//
// The mailbox property interface and the GET_CUSTOMER_OTP tag are documented
// hardware ABIs; this is an independent implementation.

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// /dev/vcio mailbox property ioctl
#define VCIO_MBOX_PROPERTY _IOWR(100, 0, char *)

// Mailbox property tag: read customer OTP rows
#define TAG_GET_CUSTOMER_OTP 0x00030021u

#define OTP_FIRST_ROW 0
#define OTP_ROW_COUNT 8 // 8 rows * 32 bits = 256-bit key

static int fail(const char *what)
{
    fprintf(stderr, "unlock: %s: %s\n", what, strerror(errno));
    return 1;
}

int main(void)
{
    int fd = open("/dev/vcio", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return fail("open /dev/vcio");

    // Property buffer (all u32, native endian):
    //   [0] total byte size
    //   [1] request code (0)
    //   tag:
    //   [2] tag id
    //   [3] value buffer size in bytes
    //   [4] request/response code
    //   [5] first row index   (request)
    //   [6] row count         (request)
    //   [7..] row values      (response)
    //   end tag: 0
    const unsigned values = OTP_ROW_COUNT;
    const unsigned tag_value_bytes = (2 + values) * sizeof(uint32_t);
    uint32_t msg[7 + OTP_ROW_COUNT + 1];
    unsigned i = 0;

    msg[i++] = sizeof(msg);
    msg[i++] = 0;
    msg[i++] = TAG_GET_CUSTOMER_OTP;
    msg[i++] = tag_value_bytes;
    msg[i++] = 0;
    msg[i++] = OTP_FIRST_ROW;
    msg[i++] = OTP_ROW_COUNT;
    for (unsigned r = 0; r < OTP_ROW_COUNT; r++)
        msg[i++] = 0;
    msg[i++] = 0; // end tag

    if (ioctl(fd, VCIO_MBOX_PROPERTY, msg) < 0) {
        close(fd);
        return fail("vcio mailbox ioctl");
    }
    close(fd);

    if (msg[1] != 0x80000000u) {
        fprintf(stderr, "unlock: mailbox returned error code 0x%08x\n", msg[1]);
        return 1;
    }

    // Response rows start at index 7 (after the 2 request words in the tag).
    const uint32_t *rows = &msg[7];
    char out[OTP_ROW_COUNT * 8 + 2];
    char *p = out;
    int all_zero = 1;
    for (unsigned r = 0; r < OTP_ROW_COUNT; r++) {
        if (rows[r] != 0)
            all_zero = 0;
        p += sprintf(p, "%08x", rows[r]);
    }

    if (all_zero) {
        // Unprovisioned device: no key in OTP. A bootstrap helper would handle
        // first-boot provisioning; the bare unlock helper cannot.
        fprintf(stderr, "unlock: customer OTP is empty (device not provisioned)\n");
        return 1;
    }

    *p++ = '\n';
    if (write(STDOUT_FILENO, out, (size_t)(p - out)) < 0)
        return fail("write key");

    return 0;
}
