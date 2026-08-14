// SPDX-License-Identifier: Apache-2.0
//
// First-boot conversion of a plaintext rootfs to an encrypted one.
//
// Runs as cryptinit's `cmd:` key helper, so cryptinit never learns that a
// conversion happened — it asks for a key and eventually gets one. That is
// nerves_cryptinit's stated boundary: board-specific work stays in userspace
// helpers and out of the init.
//
// Why this is safe to do at all: dm-verity sits *on top* of dm-crypt, so
// encrypting the whole partition — filesystem and appended hash tree together
// — leaves the plaintext verity sees byte-for-byte identical. The root hash
// does not change, so the signed cmdline stays valid and nothing needs
// re-signing. That is what makes in-place conversion possible without a new
// signature.
//
// The conversion stages through the spare A/B rootfs slot rather than RAM.
// ex_verity staged into a tmpfs the size of the partition and then wrote back
// over the source, which needs the whole image in memory and leaves an
// unrecoverable window: a power cut mid-writeback destroys the only copy.
// Staging to a real partition removes both problems and makes every
// interruption resumable.

#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include <stdint.h>

// Where the conversion has got to, decided by looking at the two partitions.
enum bootstrap_state {
    // rootfs decrypts to a filesystem: already converted, just hand over the key.
    BOOTSTRAP_DONE,

    // rootfs is still plaintext: convert it.
    BOOTSTRAP_PLAINTEXT,

    // rootfs is neither plaintext nor decryptable, but the staging partition
    // holds a complete encrypted image. We died during the write-back; finish it.
    BOOTSTRAP_STAGED,

    // Neither partition makes sense. Do not touch anything: whatever is wrong,
    // writing over it cannot help and can destroy a recoverable device.
    BOOTSTRAP_UNKNOWN
};

struct bootstrap_config {
    const char *rootfs_device;   // the partition cryptinit will mount
    const char *staging_device;  // the spare A/B slot, same size
    const char *cipher;          // must match fwup's offline encryption
};

// Classify the current state without modifying anything.
enum bootstrap_state bootstrap_detect(const struct bootstrap_config *cfg,
                                      const char *key_hex);

// Run the conversion to completion from whatever state the device is in.
// Idempotent: safe to call on an already-converted device, and safe to call
// again after being interrupted at any point. Returns 0 on success.
int bootstrap_run(const struct bootstrap_config *cfg, const char *key_hex);

// True when `head` starts with the squashfs magic, i.e. plaintext filesystem.
int bootstrap_is_filesystem(const void *head);

// Byte offset of the dm-verity superblock, derived from the squashfs
// superblock in `head` the same way nerves_cryptinit derives it: the
// filesystem size rounded up to the verity block size. Returns 0 if `head` is
// not a squashfs superblock.
uint64_t bootstrap_verity_offset(const void *head);

// Enough of a squashfs superblock to reach bytes_used at offset 40.
#define BOOTSTRAP_HEAD_LEN 48
#define BOOTSTRAP_MAGIC_LEN 4
#define BOOTSTRAP_VERITY_SIG_LEN 6

#endif
