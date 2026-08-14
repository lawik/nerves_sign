// SPDX-License-Identifier: Apache-2.0
//
// The dm-crypt seam.
//
// On a device these two functions map dm-crypt onto a block device and read or
// write through it. On a build host the test binary links a reversible stand-in
// instead, which is the only way to exercise the conversion state machine —
// the interesting cases are power loss between stages and resuming a half
// written partition, and neither is reachable through QEMU or a Pi.
//
// Everything above this line is ordinary file I/O, so it behaves identically
// against a block device and against a regular file in a test.

#ifndef CRYPT_H
#define CRYPT_H

#include <stddef.h>
#include <stdint.h>

// Copy `bytes` from `src` to `dst`, encrypting on the way. `dst` receives
// ciphertext that decrypts back to exactly the bytes read from `src`.
// Durable on return: the data has reached the device.
int crypt_encrypt(const char *src, const char *dst, const char *cipher,
                  const char *key_hex, uint64_t bytes);

// Read `len` plaintext bytes from `device` at `offset`, decrypting.
// Returns 0 on success, -1 on failure.
int crypt_read_plain(const char *device, const char *cipher, const char *key_hex,
                     uint64_t offset, void *buf, size_t len);

#endif
