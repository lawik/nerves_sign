// SPDX-License-Identifier: Apache-2.0
//
// VideoCore mailbox property interface.
//
// Isolated behind one function so the OTP code above it is testable on a host
// without a Pi: the test build links a fake that keeps rows in memory.

#ifndef MAILBOX_H
#define MAILBOX_H

#include <stdint.h>

// Send a property-interface message. `msg` is the full buffer, native endian,
// mutated in place with the response. Returns 0 on success, -1 with errno set.
int mailbox_property(uint32_t *msg);

#endif
