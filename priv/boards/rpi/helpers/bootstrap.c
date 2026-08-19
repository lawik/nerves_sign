// SPDX-License-Identifier: Apache-2.0

#include "bootstrap.h"

#include "blockdev.h"
#include "crypt.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

// squashfs, little endian. The rootfs nerves_sign signs is always squashfs.
static const unsigned char SQUASHFS_MAGIC[BOOTSTRAP_MAGIC_LEN] = {'h', 's', 'q', 's'};

// dm-verity superblock signature, at the hash offset.
static const unsigned char VERITY_SIG[BOOTSTRAP_VERITY_SIG_LEN] = {'v', 'e', 'r', 'i', 't', 'y'};

// veritysetup aligns the hash tree to this, and cryptinit assumes it.
#define VERITY_BLOCK 4096

int bootstrap_is_filesystem(const void *head)
{
    return memcmp(head, SQUASHFS_MAGIC, BOOTSTRAP_MAGIC_LEN) == 0;
}

uint64_t bootstrap_verity_offset(const void *head)
{
    const unsigned char *p = head;

    if (!bootstrap_is_filesystem(head))
        return 0;

    // squashfs superblock: bytes_used is a little-endian u64 at offset 40.
    uint64_t used = 0;
    for (int i = 7; i >= 0; i--)
        used = (used << 8) | p[40 + i];

    return (used + VERITY_BLOCK - 1) / VERITY_BLOCK * VERITY_BLOCK;
}

// Is `device` a *completely* converted rootfs?
//
// Checking the squashfs magic alone is not enough: a copy interrupted after
// the first block has a decryptable head and a plaintext tail. The verity
// superblock is the second check — and it proves completion only because
// every writer here saves its block for LAST (see copy_marker_last and the
// encrypt path). Positionally it is NOT near the end: the image is typically
// much smaller than the partition, so the superblock sits well inside the
// copy range. A sequential copy would write it long before finishing, and an
// interruption after that point would read as converted here and then fail
// dm-verity at boot with the rootfs already destroyed — which is exactly what
// happened on the first hardware run.
static int fully_converted(const char *device, const char *cipher, const char *key_hex)
{
    unsigned char head[BOOTSTRAP_HEAD_LEN];

    if (crypt_read_plain(device, cipher, key_hex, 0, head, sizeof(head)) < 0)
        return 0;

    uint64_t hash_offset = bootstrap_verity_offset(head);
    if (hash_offset == 0)
        return 0;

    unsigned char sig[BOOTSTRAP_VERITY_SIG_LEN];
    if (crypt_read_plain(device, cipher, key_hex, hash_offset, sig, sizeof(sig)) < 0)
        return 0;

    return memcmp(sig, VERITY_SIG, sizeof(sig)) == 0;
}

enum bootstrap_state bootstrap_detect(const struct bootstrap_config *cfg,
                                      const char *key_hex)
{
    unsigned char head[BOOTSTRAP_HEAD_LEN];

    if (blockdev_read_at(cfg->rootfs_device, 0, head, sizeof(head)) < 0)
        return BOOTSTRAP_UNKNOWN;

    // Checked before the plaintext test: a converted device must never be read
    // as "needs converting", or we would encrypt ciphertext and lose the rootfs.
    if (fully_converted(cfg->rootfs_device, cfg->cipher, key_hex))
        return BOOTSTRAP_DONE;

    if (bootstrap_is_filesystem(head))
        return BOOTSTRAP_PLAINTEXT;

    // Neither: either we died partway through writing ciphertext back over the
    // rootfs, or something else entirely is wrong. The staging slot decides.
    if (fully_converted(cfg->staging_device, cfg->cipher, key_hex))
        return BOOTSTRAP_STAGED;

    return BOOTSTRAP_UNKNOWN;
}

static int same_size(const struct bootstrap_config *cfg, uint64_t *bytes)
{
    int64_t root = blockdev_size(cfg->rootfs_device);
    int64_t staging = blockdev_size(cfg->staging_device);

    if (root < 0 || staging < 0)
        return -1;

    // A staging slot smaller than the rootfs would truncate the image and a
    // larger one would leave a tail that decrypts to nothing. The A/B layout
    // makes them equal; refuse if the project's layout does not.
    if (root != staging) {
        fprintf(stderr,
                "bootstrap: %s is %lld bytes but %s is %lld; the staging slot must match\n",
                cfg->rootfs_device, (long long)root, cfg->staging_device,
                (long long)staging);
        errno = EINVAL;
        return -1;
    }

    *bytes = (uint64_t)root;
    return 0;
}

// The byte offset of the verity superblock on a converted device, recovered
// by decrypting its head. 0 if the head does not decrypt to a filesystem.
static uint64_t converted_verity_offset(const char *device, const char *cipher,
                                        const char *key_hex)
{
    unsigned char head[BOOTSTRAP_HEAD_LEN];

    if (crypt_read_plain(device, cipher, key_hex, 0, head, sizeof(head)) < 0)
        return 0;

    return bootstrap_verity_offset(head);
}

// Copy `bytes` from staging to rootfs with the verity-superblock block LAST.
// That block is fully_converted's completion marker: writing it last means an
// interruption at any earlier point leaves a rootfs that does not read as
// converted, so the next boot resumes from BOOTSTRAP_STAGED instead of
// mounting a torn image.
static int copy_marker_last(const char *src, const char *dst, uint64_t marker,
                            uint64_t bytes)
{
    if (marker == 0 || marker + VERITY_BLOCK > bytes)
        return blockdev_copy(src, dst, bytes);

    if (blockdev_copy_range(src, dst, 0, marker) < 0)
        return -1;

    if (blockdev_copy_range(src, dst, marker + VERITY_BLOCK,
                            bytes - marker - VERITY_BLOCK) < 0)
        return -1;

    return blockdev_copy_range(src, dst, marker, VERITY_BLOCK);
}

// Write the staged ciphertext back over the rootfs. This is the destructive
// step: until it completes the rootfs is unreadable, which is exactly what
// BOOTSTRAP_STAGED detects on the next boot so it can be run again.
static int write_back(const struct bootstrap_config *cfg, const char *key_hex,
                      uint64_t bytes)
{
    fprintf(stderr, "bootstrap: writing the encrypted image back over %s\n",
            cfg->rootfs_device);

    uint64_t marker = converted_verity_offset(cfg->staging_device, cfg->cipher, key_hex);

    if (copy_marker_last(cfg->staging_device, cfg->rootfs_device, marker, bytes) < 0)
        return -1;

    if (!fully_converted(cfg->rootfs_device, cfg->cipher, key_hex)) {
        fprintf(stderr, "bootstrap: %s does not decrypt after write-back\n",
                cfg->rootfs_device);
        errno = EIO;
        return -1;
    }

    return 0;
}

int bootstrap_run(const struct bootstrap_config *cfg, const char *key_hex)
{
    uint64_t bytes;

    switch (bootstrap_detect(cfg, key_hex)) {
    case BOOTSTRAP_DONE:
        return 0;

    case BOOTSTRAP_STAGED:
        if (same_size(cfg, &bytes) < 0)
            return -1;

        return write_back(cfg, key_hex, bytes);

    case BOOTSTRAP_PLAINTEXT:
        if (same_size(cfg, &bytes) < 0)
            return -1;

        fprintf(stderr, "bootstrap: encrypting %s into %s (%llu bytes)\n",
                cfg->rootfs_device, cfg->staging_device, (unsigned long long)bytes);

        // The same marker-last ordering as the write-back: encrypt everything
        // around the verity-superblock block, then that block. An encrypt pass
        // interrupted anywhere leaves a staging slot that does NOT read as
        // fully converted, so the next boot re-runs from PLAINTEXT instead of
        // write-backing a torn image. The marker offset comes from the
        // plaintext squashfs head, which detect just validated.
        {
            unsigned char head[BOOTSTRAP_HEAD_LEN];
            uint64_t marker = 0;

            if (blockdev_read_at(cfg->rootfs_device, 0, head, sizeof(head)) == 0)
                marker = bootstrap_verity_offset(head);

            if (marker == 0 || marker + VERITY_BLOCK > bytes) {
                if (crypt_encrypt(cfg->rootfs_device, cfg->staging_device, cfg->cipher,
                                  key_hex, 0, bytes) < 0)
                    return -1;
            } else {
                if (crypt_encrypt(cfg->rootfs_device, cfg->staging_device, cfg->cipher,
                                  key_hex, 0, marker) < 0)
                    return -1;

                if (crypt_encrypt(cfg->rootfs_device, cfg->staging_device, cfg->cipher,
                                  key_hex, marker + VERITY_BLOCK,
                                  bytes - marker - VERITY_BLOCK) < 0)
                    return -1;

                if (crypt_encrypt(cfg->rootfs_device, cfg->staging_device, cfg->cipher,
                                  key_hex, marker, VERITY_BLOCK) < 0)
                    return -1;
            }
        }

        // Verify the staged copy before overwriting the only plaintext we have.
        // Up to this point every failure is harmless: the rootfs is untouched.
        if (!fully_converted(cfg->staging_device, cfg->cipher, key_hex)) {
            fprintf(stderr, "bootstrap: staged image does not decrypt; leaving %s alone\n",
                    cfg->rootfs_device);
            errno = EIO;
            return -1;
        }

        return write_back(cfg, key_hex, bytes);

    case BOOTSTRAP_UNKNOWN:
    default:
        fprintf(stderr,
                "bootstrap: %s is neither a filesystem nor decryptable, and %s holds no "
                "staged image. Refusing to write anything.\n",
                cfg->rootfs_device, cfg->staging_device);
        errno = EINVAL;
        return -1;
    }
}
