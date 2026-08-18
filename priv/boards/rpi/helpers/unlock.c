// SPDX-License-Identifier: Apache-2.0
//
// nerves_sign default key helper for Raspberry Pi boards that expose the
// device private key rows via the VideoCore mailbox (Pi 4 / CM4 and friends).
//
// Reads the private key rows and prints the key as lowercase hex
// on stdout, which is the contract nerves_cryptinit's `cmd:` key source
// expects (64 hex chars for a 256-bit key, exit 0).
//
// It only reads. An unprovisioned device is an error here, not something to
// fix: burning a key and converting a plaintext rootfs is the bootstrap
// helper's job, and doing it by accident is not recoverable.
//
// Build static against the musl Nerves toolchain, install at /usr/sbin/unlock,
// and reference it from initramfs.conf:
//
//     rootfs_key = cmd:/usr/sbin/unlock
//
// Projects can point nerves_sign at an alternate source via
// `config :nerves_sign, key_helper_source: "path/to/your.c"`.
//
// The mailbox property interface and the customer OTP tags are documented
// hardware ABIs; this is an independent implementation.

#include "otp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    uint32_t rows[OTP_ROW_COUNT];

    if (otp_read(rows) < 0) {
        perror("unlock: reading the device private key");
        return 1;
    }

    if (otp_blank(rows)) {
        fprintf(stderr, "unlock: private key rows are empty (device not provisioned)\n");
        return 1;
    }

    char out[OTP_HEX_LEN + 2];
    otp_format_hex(rows, out);
    out[OTP_HEX_LEN] = '\n';

    if (write(STDOUT_FILENO, out, OTP_HEX_LEN + 1) < 0) {
        perror("unlock: writing key");
        return 1;
    }

    return 0;
}
