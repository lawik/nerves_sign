// SPDX-License-Identifier: Apache-2.0

#include "mailbox.h"

#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>

// /dev/vcio mailbox property ioctl.
#define VCIO_MBOX_PROPERTY _IOWR(100, 0, char *)

int mailbox_property(uint32_t *msg)
{
    int fd = open("/dev/vcio", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;

    int rc = ioctl(fd, VCIO_MBOX_PROPERTY, msg);
    int saved = errno;
    close(fd);
    errno = saved;

    return rc < 0 ? -1 : 0;
}
