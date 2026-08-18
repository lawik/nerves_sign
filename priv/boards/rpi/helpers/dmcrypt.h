// SPDX-License-Identifier: Apache-2.0
//
// A minimal dm-crypt mapper, spoken directly to /dev/mapper/control.
//
// Modelled on nerves_cryptinit's dm.c — same ABI, same table line, same
// DM_SECURE_DATA_FLAG so the kernel scrubs its copy of the key. Written
// separately rather than linked because this needs two things cryptinit's
// version does not provide, both essential here:
//
//   * the device number back, so the mapping can be opened without guessing
//     an index or waiting on devtmpfs to publish /dev/dm-N
//   * a way to tear the mapping down, so a first-boot conversion does not
//     leave a stray dm device behind for cryptinit to trip over
//
// And it returns errors rather than calling fatal(). The conversion above it
// promises to leave the rootfs alone when anything goes wrong, which it cannot
// do if a failed ioctl exits the process.

#ifndef DMCRYPT_H
#define DMCRYPT_H

#include <stddef.h>

// Map dm-crypt over `device` and write a usable path into `path_out`.
// `read_only` maps without write permission. Returns 0 on success, -1 on
// failure with a message on stderr.
int dmcrypt_open(const char *name, const char *device, const char *cipher,
                 const char *key_hex, int read_only, char *path_out, size_t path_len);

// Remove the mapping created by dmcrypt_open and clean up its node.
// Safe to call when the mapping does not exist. Returns 0 on success.
int dmcrypt_close(const char *name, const char *path);

#endif
