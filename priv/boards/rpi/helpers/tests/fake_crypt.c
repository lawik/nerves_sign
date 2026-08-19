// SPDX-License-Identifier: Apache-2.0
//
// A reversible stand-in for dm-crypt. Not a cipher and not pretending to be
// one: it exists so the conversion state machine can be driven through the
// cases that decide whether a device survives — power loss between stages,
// resuming a half-written rootfs, running twice — none of which are reachable
// on a Pi or in QEMU.
//
// It keeps the two properties the state machine depends on: encryption is
// reversible with the right key, and produces something that does NOT look
// like a filesystem with the wrong one (or none).

#include "../crypt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned fake_crypt_encrypt_calls;

// Fail once the NEXT `fail_after_bytes` bytes of encryption have been
// processed, to model a power cut mid-stage. The budget persists across
// crypt_encrypt calls until it fires (the conversion now encrypts in several
// ordered ranges, and a power cut does not care about range boundaries), then
// disarms so a retry can succeed. Granularity is the 4K copy chunk: the chunk
// that exhausts the budget is fully written before the failure, matching
// "bytes written so far are real".
static uint64_t fail_after_bytes;
static uint64_t consumed_since_arm;

void fake_crypt_reset(void)
{
    fake_crypt_encrypt_calls = 0;
    fail_after_bytes = 0;
    consumed_since_arm = 0;
}

void fake_crypt_fail_after(uint64_t bytes)
{
    fail_after_bytes = bytes;
    consumed_since_arm = 0;
}

static unsigned char keystream(const char *key_hex, uint64_t offset)
{
    // Position dependent so a shifted image does not decrypt, which is what
    // makes the truncation and size-mismatch cases meaningful.
    unsigned char k = (unsigned char)key_hex[offset % strlen(key_hex)];
    return (unsigned char)(k ^ (unsigned char)(offset & 0xff) ^ 0x5a);
}

static int transform(const char *src, const char *dst, const char *key_hex,
                     uint64_t offset, uint64_t bytes)
{
    int in = open(src, O_RDONLY);
    if (in < 0)
        return -1;

    int out = open(dst, O_WRONLY | O_CREAT, 0600);
    if (out < 0) {
        close(in);
        return -1;
    }

    if (lseek(in, (off_t)offset, SEEK_SET) < 0 || lseek(out, (off_t)offset, SEEK_SET) < 0) {
        close(in);
        close(out);
        return -1;
    }

    int rc = 0;
    uint64_t off = 0;
    unsigned char buf[4096];

    while (off < bytes) {
        size_t want = bytes - off < sizeof(buf) ? (size_t)(bytes - off) : sizeof(buf);
        ssize_t n = read(in, buf, want);
        if (n <= 0) {
            rc = -1;
            break;
        }

        // The keystream position is the ABSOLUTE device offset, so a range
        // encrypted at offset N decrypts at offset N and nowhere else — the
        // property the real dm-crypt sector IVs provide.
        for (ssize_t i = 0; i < n; i++)
            buf[i] ^= keystream(key_hex, offset + off + (uint64_t)i);

        if (write(out, buf, (size_t)n) != n) {
            rc = -1;
            break;
        }

        off += (uint64_t)n;

        if (fail_after_bytes) {
            consumed_since_arm += (uint64_t)n;
            if (consumed_since_arm >= fail_after_bytes) {
                // Bytes written so far are real; the rest never happened.
                fail_after_bytes = 0;
                errno = EIO;
                rc = -1;
                break;
            }
        }
    }

    close(in);
    close(out);
    return rc;
}

int crypt_encrypt(const char *src, const char *dst, const char *cipher,
                  const char *key_hex, uint64_t offset, uint64_t bytes)
{
    (void)cipher;
    fake_crypt_encrypt_calls++;

    return transform(src, dst, key_hex, offset, bytes);
}

int crypt_read_plain(const char *device, const char *cipher, const char *key_hex,
                     uint64_t offset, void *buf, size_t len)
{
    (void)cipher;

    int fd = open(device, O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t n = pread(fd, buf, len, (off_t)offset);
    close(fd);

    if (n < 0 || (size_t)n != len)
        return -1;

    unsigned char *p = buf;
    for (size_t i = 0; i < len; i++)
        p[i] ^= keystream(key_hex, offset + i);

    return 0;
}
