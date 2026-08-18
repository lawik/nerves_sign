// SPDX-License-Identifier: Apache-2.0
//
// An in-memory stand-in for the VideoCore mailbox, so the OTP logic above it
// can be tested on a build host. It models the one property that matters and
// is impossible to explore on real hardware: OTP bits are one-time, so a burn
// ORs into the rows and can never clear a bit.

#include "fake_mailbox.h"

#include "../otp.h"

#include <string.h>

// The device private key rows, matching otp.c. Deliberately spelled out here
// rather than included: if the tags in otp.c change, these tests must fail
// until someone confirms the new ones are right, because the write is a fuse.
#define TAG_GET_PRIVATE_KEY 0x00030081u
#define TAG_SET_PRIVATE_KEY 0x00038081u
#define MBOX_RESPONSE_OK 0x80000000u
#define MSG_ROWS_AT 7

static uint32_t fake_rows[OTP_ROW_COUNT];
static int fail_next;
static uint32_t error_code;

unsigned fake_mailbox_writes;

void fake_mailbox_reset(void)
{
    memset(fake_rows, 0, sizeof(fake_rows));
    fake_mailbox_writes = 0;
    fail_next = 0;
    error_code = 0;
}

void fake_mailbox_set_rows(const uint32_t *rows)
{
    memcpy(fake_rows, rows, sizeof(fake_rows));
}

void fake_mailbox_get_rows(uint32_t *rows)
{
    memcpy(rows, fake_rows, sizeof(fake_rows));
}

void fake_mailbox_fail_next(uint32_t code)
{
    fail_next = 1;
    error_code = code;
}

int mailbox_property(uint32_t *msg)
{
    if (fail_next) {
        fail_next = 0;
        msg[1] = error_code;
        return 0;
    }

    switch (msg[2]) {
    case TAG_GET_PRIVATE_KEY:
        memcpy(&msg[MSG_ROWS_AT], fake_rows, sizeof(fake_rows));
        break;

    case TAG_SET_PRIVATE_KEY:
        fake_mailbox_writes++;
        // One-time programmable: bits only ever go 0 -> 1.
        for (unsigned r = 0; r < OTP_ROW_COUNT; r++)
            fake_rows[r] |= msg[MSG_ROWS_AT + r];
        break;

    default:
        msg[1] = 0;
        return 0;
    }

    msg[1] = MBOX_RESPONSE_OK;
    return 0;
}
