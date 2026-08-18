// SPDX-License-Identifier: Apache-2.0

#include "dmcrypt.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

// One buffer carries the fixed dm_ioctl header plus per-call data. 16 KB is
// well clear of the longest table line we build, even with a 256-bit key.
#define DM_BUFFER_SIZE 16384

#define DEFAULT_CIPHER "aes-xts-plain64"

static void init_header(struct dm_ioctl *dm, const char *name)
{
    memset(dm, 0, sizeof(*dm));
    dm->version[0] = DM_VERSION_MAJOR;
    dm->version[1] = DM_VERSION_MINOR;
    dm->version[2] = DM_VERSION_PATCHLEVEL;
    dm->data_size = DM_BUFFER_SIZE;
    dm->data_start = sizeof(*dm);
    snprintf(dm->name, sizeof(dm->name), "%s", name);
}

// dm targets are sized in 512-byte sectors regardless of the device's own
// logical block size.
static int64_t sector_count(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    uint64_t bytes;
    if (ioctl(fd, BLKGETSIZE64, &bytes) < 0) {
        // Regular files have no BLKGETSIZE64; fall back to their size so this
        // can be exercised against an image file.
        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            return -1;
        }
        bytes = (uint64_t)st.st_size;
    }

    close(fd);
    return (int64_t)(bytes / 512);
}

int dmcrypt_open(const char *name, const char *device, const char *cipher,
                 const char *key_hex, int read_only, char *path_out, size_t path_len)
{
    if (!cipher)
        cipher = DEFAULT_CIPHER;

    int64_t sectors = sector_count(device);
    if (sectors <= 0) {
        fprintf(stderr, "dmcrypt: could not size %s\n", device);
        return -1;
    }

    int control = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
    if (control < 0) {
        fprintf(stderr, "dmcrypt: could not open /dev/mapper/control (CONFIG_DM_CRYPT?)\n");
        return -1;
    }

    uint8_t buffer[DM_BUFFER_SIZE];
    struct dm_ioctl *dm = (struct dm_ioctl *)buffer;
    uint32_t ro_flag = read_only ? DM_READONLY_FLAG : 0;

    // 1. Create the device. The kernel fills in dm->dev with its device number,
    //    which is how we find it afterwards without guessing.
    init_header(dm, name);
    snprintf(dm->uuid, sizeof(dm->uuid), "CRYPT-PLAIN-%s", name);

    if (ioctl(control, DM_DEV_CREATE, buffer) < 0) {
        fprintf(stderr, "dmcrypt: DM_DEV_CREATE for %s: %s\n", name, strerror(errno));
        close(control);
        return -1;
    }

    uint64_t dev = dm->dev;

    // 2. Load the table. DM_SECURE_DATA_FLAG asks the kernel to scrub its copy
    //    of the key, which matters because the line below contains it.
    init_header(dm, name);
    dm->target_count = 1;
    dm->flags = DM_SECURE_DATA_FLAG | ro_flag;

    struct dm_target_spec *target = (struct dm_target_spec *)(buffer + dm->data_start);
    target->sector_start = 0;
    target->length = (uint64_t)sectors;
    target->status = 0;
    target->next = 0;
    snprintf(target->target_type, sizeof(target->target_type), "crypt");

    char *params = (char *)(target + 1);
    size_t params_max = DM_BUFFER_SIZE - dm->data_start - sizeof(struct dm_target_spec);
    int n = snprintf(params, params_max, "%s %s 0 %s 0", cipher, key_hex, device);

    if (n < 0 || (size_t)n >= params_max) {
        fprintf(stderr, "dmcrypt: table line too long\n");
        close(control);
        dmcrypt_close(name, NULL);
        return -1;
    }

    if (ioctl(control, DM_TABLE_LOAD, buffer) < 0) {
        fprintf(stderr, "dmcrypt: DM_TABLE_LOAD for %s (cipher %s): %s\n", name, cipher,
                strerror(errno));
        close(control);
        dmcrypt_close(name, NULL);
        return -1;
    }

    // 3. Resume: DM_DEV_SUSPEND with no suspend flag means resume.
    init_header(dm, name);
    dm->flags = DM_SECURE_DATA_FLAG | ro_flag;

    if (ioctl(control, DM_DEV_SUSPEND, buffer) < 0) {
        fprintf(stderr, "dmcrypt: DM_DEV_SUSPEND for %s: %s\n", name, strerror(errno));
        close(control);
        dmcrypt_close(name, NULL);
        return -1;
    }

    close(control);

    // Make our own node from the device number rather than waiting for
    // devtmpfs to publish /dev/dm-N. In an initramfs there is no udev and the
    // timing is not ours to rely on.
    if ((size_t)snprintf(path_out, path_len, "/dev/dmcrypt-%s", name) >= path_len) {
        dmcrypt_close(name, NULL);
        return -1;
    }

    unlink(path_out);

    if (mknod(path_out, S_IFBLK | 0600, makedev(major(dev), minor(dev))) < 0) {
        fprintf(stderr, "dmcrypt: mknod %s: %s\n", path_out, strerror(errno));
        dmcrypt_close(name, NULL);
        return -1;
    }

    return 0;
}

int dmcrypt_close(const char *name, const char *path)
{
    if (path)
        unlink(path);

    int control = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
    if (control < 0)
        return -1;

    uint8_t buffer[DM_BUFFER_SIZE];
    struct dm_ioctl *dm = (struct dm_ioctl *)buffer;

    init_header(dm, name);
    int rc = ioctl(control, DM_DEV_REMOVE, buffer);
    close(control);

    if (rc < 0 && errno != ENXIO) {
        fprintf(stderr, "dmcrypt: DM_DEV_REMOVE for %s: %s\n", name, strerror(errno));
        return -1;
    }

    return 0;
}
