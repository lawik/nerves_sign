// SPDX-License-Identifier: Apache-2.0
//
// Host tests for the first-boot conversion state machine.
//
// These are the cases that decide whether a device survives a bad moment, and
// none of them are reachable on hardware: you cannot cut power to a Pi
// mid-write on demand, and QEMU boots too late to see any of it. Regular files
// stand in for the partitions, which works because everything above the crypt
// seam is ordinary file I/O.

#include "../blockdev.h"
#include "../bootstrap.h"
#include "../crypt.h"
#include "fake_crypt.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;
static const char *current_test;

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            fprintf(stderr, "  FAIL %s:%d: %s\n", current_test, __LINE__, #cond);         \
            failures++;                                                                  \
        }                                                                                \
    } while (0)

#define KEY "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// Filesystem then hash tree, the layout veritysetup produces and cryptinit
// expects: 4096 bytes of squashfs, verity superblock at 4096.
#define FS_BYTES 4096
#define SIZE 8192

static char root_path[] = "/tmp/ns_bootstrap_root_XXXXXX";
static char stage_path[] = "/tmp/ns_bootstrap_stage_XXXXXX";

static struct bootstrap_config cfg;

static void write_file(const char *path, const unsigned char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0)
        abort();
    if (write(fd, data, len) != (ssize_t)len)
        abort();
    close(fd);
}

// A stand-in rootfs with the shape the real one has: a squashfs superblock
// whose bytes_used points at the hash tree, and a verity superblock there.
// The far-end signature is what makes a partial write-back detectable.
static void make_plaintext(unsigned char *buf, size_t len)
{
    memcpy(buf, "hsqs", 4);

    for (size_t i = 4; i < len; i++)
        buf[i] = (unsigned char)(i * 7 + 3);

    // squashfs bytes_used: little-endian u64 at offset 40.
    uint64_t used = FS_BYTES;
    for (int i = 0; i < 8; i++)
        buf[40 + i] = (unsigned char)(used >> (8 * i));

    memcpy(buf + FS_BYTES, "verity", 6);
}

static void reset(void)
{
    unsigned char plain[SIZE];
    unsigned char zeros[SIZE];

    make_plaintext(plain, sizeof(plain));
    memset(zeros, 0, sizeof(zeros));

    write_file(root_path, plain, sizeof(plain));
    write_file(stage_path, zeros, sizeof(zeros));

    fake_crypt_reset();
}

#define TEST(name)                                                                       \
    current_test = name;                                                                 \
    reset();

static int root_matches_plaintext(void)
{
    unsigned char expect[SIZE];
    unsigned char got[SIZE];

    make_plaintext(expect, sizeof(expect));

    if (blockdev_read_at(root_path, 0, got, sizeof(got)) < 0)
        return 0;

    return memcmp(expect, got, sizeof(got)) == 0;
}

// The rootfs, decrypted, must be byte-identical to what was there before.
// Anything less and dm-verity fails on the next boot: the root hash on the
// signed cmdline covers the filesystem AND the appended hash tree.
static int root_decrypts_to_original(void)
{
    unsigned char expect[SIZE];
    unsigned char got[SIZE];

    make_plaintext(expect, sizeof(expect));

    if (crypt_read_plain(root_path, cfg.cipher, KEY, 0, got, sizeof(got)) < 0)
        return 0;

    return memcmp(expect, got, sizeof(got)) == 0;
}

static void test_detects_plaintext(void)
{
    TEST("a fresh device reads as plaintext");

    CHECK(bootstrap_detect(&cfg, KEY) == BOOTSTRAP_PLAINTEXT);
}

static void test_converts(void)
{
    TEST("conversion encrypts the rootfs in place");

    CHECK(bootstrap_run(&cfg, KEY) == 0);
    CHECK(bootstrap_detect(&cfg, KEY) == BOOTSTRAP_DONE);

    // Not plaintext any more...
    CHECK(!root_matches_plaintext());
    // ...but decrypts back to exactly what was there, which is what keeps the
    // verity root hash on the signed cmdline valid.
    CHECK(root_decrypts_to_original());
}

static void test_idempotent(void)
{
    TEST("running again on a converted device does nothing");

    CHECK(bootstrap_run(&cfg, KEY) == 0);
    unsigned after_first = fake_crypt_encrypt_calls;

    CHECK(bootstrap_run(&cfg, KEY) == 0);
    CHECK(bootstrap_run(&cfg, KEY) == 0);

    // Encrypting an already-encrypted rootfs would destroy it permanently.
    CHECK(fake_crypt_encrypt_calls == after_first);
    CHECK(root_decrypts_to_original());
}

static void test_power_loss_during_staging(void)
{
    TEST("power loss while staging leaves the rootfs untouched");

    fake_crypt_fail_after(2048);
    CHECK(bootstrap_run(&cfg, KEY) == -1);

    // Nothing has been written back yet, so the device still has its plaintext
    // rootfs and boots exactly as before.
    CHECK(root_matches_plaintext());
    CHECK(bootstrap_detect(&cfg, KEY) == BOOTSTRAP_PLAINTEXT);

    // And a retry completes.
    CHECK(bootstrap_run(&cfg, KEY) == 0);
    CHECK(root_decrypts_to_original());
}

static void test_power_loss_during_write_back(void)
{
    TEST("power loss during write-back is detected and resumed");

    // Stage a complete encrypted image, then simulate dying partway through
    // copying it back: the rootfs is half ciphertext, half plaintext.
    CHECK(crypt_encrypt(root_path, stage_path, cfg.cipher, KEY, SIZE) == 0);

    unsigned char staged[SIZE];
    unsigned char partial[SIZE];
    CHECK(blockdev_read_at(stage_path, 0, staged, sizeof(staged)) == 0);
    CHECK(blockdev_read_at(root_path, 0, partial, sizeof(partial)) == 0);

    // Died after the first blocks: the head is ciphertext, the verity
    // superblock at the far end is still plaintext. Checking only the squashfs
    // magic would call this converted and hand back a key for a broken rootfs.
    memcpy(partial, staged, 3000);
    write_file(root_path, partial, sizeof(partial));

    // The rootfs is now neither a filesystem nor decryptable...
    CHECK(bootstrap_detect(&cfg, KEY) == BOOTSTRAP_STAGED);

    // ...and the staged copy is enough to finish the job.
    CHECK(bootstrap_run(&cfg, KEY) == 0);
    CHECK(root_decrypts_to_original());
    CHECK(bootstrap_detect(&cfg, KEY) == BOOTSTRAP_DONE);
}

static void test_refuses_unknown(void)
{
    TEST("garbage on both partitions is left alone");

    unsigned char junk[SIZE];
    memset(junk, 0xAB, sizeof(junk));
    write_file(root_path, junk, sizeof(junk));

    CHECK(bootstrap_detect(&cfg, KEY) == BOOTSTRAP_UNKNOWN);
    CHECK(bootstrap_run(&cfg, KEY) == -1);

    // Writing over a device we do not understand cannot help and can destroy
    // something recoverable.
    unsigned char after[SIZE];
    CHECK(blockdev_read_at(root_path, 0, after, sizeof(after)) == 0);
    CHECK(memcmp(junk, after, sizeof(junk)) == 0);
    CHECK(fake_crypt_encrypt_calls == 0);
}

static void test_wrong_key_does_not_look_converted(void)
{
    TEST("a converted device with the wrong key is not mistaken for done");

    CHECK(bootstrap_run(&cfg, KEY) == 0);

    const char *other = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    // Re-encrypting under a different key would ruin it; the state machine must
    // refuse rather than "convert" again.
    CHECK(bootstrap_detect(&cfg, other) == BOOTSTRAP_UNKNOWN);
    CHECK(bootstrap_run(&cfg, other) == -1);
    CHECK(root_decrypts_to_original());
}

static void test_size_mismatch_refused(void)
{
    TEST("a staging slot of the wrong size is refused");

    // Truncate the staging file so it cannot hold the whole image.
    int fd = open(stage_path, O_WRONLY);
    CHECK(fd >= 0);
    CHECK(ftruncate(fd, SIZE / 2) == 0);
    close(fd);

    CHECK(bootstrap_run(&cfg, KEY) == -1);

    // A short staging slot would silently truncate the rootfs, so nothing is
    // written and the device still boots.
    CHECK(root_matches_plaintext());
}

static void test_magic_check(void)
{
    TEST("filesystem detection is the squashfs magic");

    CHECK(bootstrap_is_filesystem("hsqs") == 1);
    CHECK(bootstrap_is_filesystem("hsq") == 0);
    CHECK(bootstrap_is_filesystem("\0\0\0\0") == 0);
}

static void test_verity_offset(void)
{
    TEST("the verity offset comes from the squashfs superblock");

    unsigned char head[BOOTSTRAP_HEAD_LEN];
    unsigned char whole[SIZE];
    make_plaintext(whole, sizeof(whole));
    memcpy(head, whole, sizeof(head));

    // Same derivation cryptinit does, so both agree on where the tree starts.
    CHECK(bootstrap_verity_offset(head) == FS_BYTES);

    // Unaligned filesystems round up to the verity block size.
    uint64_t used = 4097;
    for (int i = 0; i < 8; i++)
        head[40 + i] = (unsigned char)(used >> (8 * i));
    CHECK(bootstrap_verity_offset(head) == 8192);

    CHECK(bootstrap_verity_offset("nope") == 0);
}

static void test_partial_write_back_is_not_done(void)
{
    TEST("a head-only write-back does not read as converted");

    unsigned char staged[SIZE];
    unsigned char partial[SIZE];

    CHECK(crypt_encrypt(root_path, stage_path, cfg.cipher, KEY, SIZE) == 0);
    CHECK(blockdev_read_at(stage_path, 0, staged, sizeof(staged)) == 0);
    CHECK(blockdev_read_at(root_path, 0, partial, sizeof(partial)) == 0);

    // Just the first block: enough for the squashfs magic to decrypt, nowhere
    // near the verity superblock.
    memcpy(partial, staged, 512);
    write_file(root_path, partial, sizeof(partial));

    CHECK(bootstrap_detect(&cfg, KEY) != BOOTSTRAP_DONE);
}

int main(void)
{
    int fd;

    fd = mkstemp(root_path);
    if (fd < 0)
        abort();
    close(fd);

    fd = mkstemp(stage_path);
    if (fd < 0)
        abort();
    close(fd);

    cfg.rootfs_device = root_path;
    cfg.staging_device = stage_path;
    cfg.cipher = "aes-xts-plain64";

    test_magic_check();
    test_verity_offset();
    test_detects_plaintext();
    test_partial_write_back_is_not_done();
    test_converts();
    test_idempotent();
    test_power_loss_during_staging();
    test_power_loss_during_write_back();
    test_refuses_unknown();
    test_wrong_key_does_not_look_converted();
    test_size_mismatch_refused();

    unlink(root_path);
    unlink(stage_path);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("bootstrap: all checks passed\n");
    return 0;
}
