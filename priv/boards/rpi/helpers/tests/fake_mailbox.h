// SPDX-License-Identifier: Apache-2.0

#ifndef FAKE_MAILBOX_H
#define FAKE_MAILBOX_H

#include <stdint.h>

extern unsigned fake_mailbox_writes;

void fake_mailbox_reset(void);
void fake_mailbox_set_rows(const uint32_t *rows);
void fake_mailbox_get_rows(uint32_t *rows);
void fake_mailbox_fail_next(uint32_t code);

#endif
