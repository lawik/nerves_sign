// SPDX-License-Identifier: Apache-2.0
//
// Block device helpers. Plain syscalls, no dd: the copy is a read/write loop
// and durability is fdatasync, so every stage boundary is a point the device
// can lose power at with a known outcome.

#ifndef BLOCKDEV_H
#define BLOCKDEV_H

#include <stddef.h>
#include <stdint.h>

// Size of a block device or regular file in bytes. -1 on failure.
int64_t blockdev_size(const char *path);

// Copy `bytes` from `src` to `dst` verbatim and fdatasync before returning.
int blockdev_copy(const char *src, const char *dst, uint64_t bytes);

// Copy `bytes` from `src` to `dst`, both starting at `offset`, and fdatasync.
// The range form exists so callers can order writes: the conversion writes
// the verity-superblock block last, as a completion marker.
int blockdev_copy_range(const char *src, const char *dst, uint64_t offset, uint64_t bytes);

// Read `len` bytes from `path` at `offset`.
int blockdev_read_at(const char *path, uint64_t offset, void *buf, size_t len);

#endif
