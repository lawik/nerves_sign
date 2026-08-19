// SPDX-License-Identifier: Apache-2.0
//
// The on-device side of the crypt seam. Maps dm-crypt onto the destination
// block device and does ordinary file I/O through it.
//
// Note what is absent: no loop device, because dm-crypt maps straight onto the
// partition and there is no file to loop-mount; and no dd, because a
// read/write loop with an explicit fdatasync is both smaller and gives a
// defined point at which the data has actually reached the medium.

#include "crypt.h"

#include "blockdev.h"
#include "dmcrypt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define ENCRYPT_NAME "ns-bootstrap-enc"
#define READ_NAME "ns-bootstrap-read"

int crypt_encrypt(const char *src, const char *dst, const char *cipher,
                  const char *key_hex, uint64_t offset, uint64_t bytes)
{
    char mapped[64];

    // Writing plaintext into the mapping is what encrypts it: the ciphertext
    // lands on `dst` underneath.
    if (dmcrypt_open(ENCRYPT_NAME, dst, cipher, key_hex, 0, mapped, sizeof(mapped)) < 0)
        return -1;

    int rc = blockdev_copy_range(src, mapped, offset, bytes);
    int saved = errno;

    // Tear the mapping down whether or not the copy worked. Leaving it behind
    // would collide with the mapping cryptinit sets up moments later.
    if (dmcrypt_close(ENCRYPT_NAME, mapped) < 0 && rc == 0) {
        rc = -1;
        saved = EIO;
    }

    errno = saved;
    return rc;
}

int crypt_read_plain(const char *device, const char *cipher, const char *key_hex,
                     uint64_t offset, void *buf, size_t len)
{
    char mapped[64];

    // Read-only: this is used to inspect a device before deciding whether to
    // write to it, and a mapping that cannot write cannot damage anything.
    if (dmcrypt_open(READ_NAME, device, cipher, key_hex, 1, mapped, sizeof(mapped)) < 0)
        return -1;

    int rc = blockdev_read_at(mapped, offset, buf, len);
    int saved = errno;

    if (dmcrypt_close(READ_NAME, mapped) < 0 && rc == 0) {
        rc = -1;
        saved = EIO;
    }

    errno = saved;
    return rc;
}
