// SPDX-License-Identifier: Apache-2.0

#include "blockdev.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define COPY_BUF (1024 * 1024)

int64_t blockdev_size(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    int64_t size;

    if (S_ISBLK(st.st_mode)) {
        uint64_t bytes;
        // A block device's st_size is 0; the size comes from an ioctl.
        if (ioctl(fd, BLKGETSIZE64, &bytes) < 0) {
            close(fd);
            return -1;
        }
        size = (int64_t)bytes;
    } else {
        size = st.st_size;
    }

    close(fd);
    return size;
}

static int write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }

    return 0;
}

int blockdev_copy(const char *src, const char *dst, uint64_t bytes)
{
    return blockdev_copy_range(src, dst, 0, bytes);
}

int blockdev_copy_range(const char *src, const char *dst, uint64_t offset, uint64_t bytes)
{
    if (bytes == 0)
        return 0;

    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return -1;

    int out = open(dst, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (out < 0) {
        close(in);
        return -1;
    }

    if (lseek(in, (off_t)offset, SEEK_SET) < 0 || lseek(out, (off_t)offset, SEEK_SET) < 0) {
        close(in);
        close(out);
        return -1;
    }

    char *buf = malloc(COPY_BUF);
    if (!buf) {
        close(in);
        close(out);
        return -1;
    }

    int rc = 0;
    uint64_t left = bytes;

    while (left > 0) {
        size_t want = left < COPY_BUF ? (size_t)left : COPY_BUF;
        ssize_t n = read(in, buf, want);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            rc = -1;
            break;
        }

        if (n == 0) {
            errno = EIO;
            rc = -1;
            break;
        }

        if (write_all(out, buf, (size_t)n) < 0) {
            rc = -1;
            break;
        }

        left -= (uint64_t)n;
    }

    // The whole point of the staged copy: a stage is only complete once it has
    // actually reached the medium, or a power cut leaves a state we cannot
    // recognise on the next boot.
    if (rc == 0 && fdatasync(out) < 0)
        rc = -1;

    free(buf);
    close(in);
    close(out);
    return rc;
}

int blockdev_read_at(const char *path, uint64_t offset, void *buf, size_t len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    size_t got = 0;
    char *p = buf;

    while (got < len) {
        ssize_t n = pread(fd, p + got, len - got, (off_t)(offset + got));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }

    close(fd);
    return got == len ? 0 : -1;
}
