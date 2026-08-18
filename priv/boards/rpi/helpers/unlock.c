// SPDX-License-Identifier: Apache-2.0
//
// nerves_sign default key helper for Raspberry Pi boards that expose the
// device private key rows via the VideoCore mailbox (Pi 4 / CM4 and friends).
//
// Reads the private key rows, derives a per-volume key from them, and prints it
// as lowercase hex on stdout — the contract nerves_cryptinit's `cmd:` key
// source expects (64 hex chars, exit 0).
//
//     rootfs_key = cmd:/usr/sbin/unlock
//     data_key   = cmd:/usr/sbin/unlock --purpose data
//
// The OTP secret is used as HKDF input keying material rather than as the key
// itself, so each volume gets a distinct key and the fused secret never leaves
// the helper. That is what makes a per-volume argument mean anything: without
// derivation every volume would share one key and the argument would be
// decoration.
//
//     --purpose STRING   HKDF info string (default "rootfs")
//     --raw              print the OTP secret verbatim, no derivation
//
// `--raw` exists for devices provisioned before derivation, or fleets that
// derive their own keys further up the stack. Those keys cannot be reproduced
// through HKDF, so the choice is permanent per device — deriving on a device
// keyed raw simply fails to decrypt.
//
// It only reads. An unprovisioned device is an error here, not something to
// fix: burning a key and converting a plaintext rootfs is bootstrap-or-derive's
// job, and doing it by accident is not recoverable.
//
// The mailbox property interface and the OTP tags are documented hardware ABIs;
// this is an independent implementation.

#include "kdf.h"
#include "otp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_PURPOSE "rootfs"

static int usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--purpose STRING] [--raw]\n"
            "\n"
            "  --purpose STRING  HKDF info string (default \"%s\")\n"
            "  --raw             print the OTP secret with no derivation, for\n"
            "                    devices provisioned before derivation existed\n",
            argv0, DEFAULT_PURPOSE);
    return 1;
}

int main(int argc, char **argv)
{
    const char *purpose = DEFAULT_PURPOSE;
    int raw = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--raw") == 0) {
            raw = 1;
        } else if (strcmp(argv[i], "--purpose") == 0 && i + 1 < argc) {
            purpose = argv[++i];
        } else {
            return usage(argv[0]);
        }
    }

    uint32_t rows[OTP_ROW_COUNT];

    if (otp_read(rows) < 0) {
        perror("unlock: reading the device private key");
        return 1;
    }

    if (otp_blank(rows)) {
        fprintf(stderr, "unlock: private key rows are empty (device not provisioned)\n");
        return 1;
    }

    char hex[OTP_HEX_LEN + 1];
    otp_format_hex(rows, hex);

    if (!raw) {
        // The rows as bytes, big-endian per row, matching the hex above so the
        // two forms describe the same secret.
        uint8_t ikm[OTP_ROW_COUNT * 4];
        for (unsigned r = 0; r < OTP_ROW_COUNT; r++) {
            ikm[r * 4] = (uint8_t)(rows[r] >> 24);
            ikm[r * 4 + 1] = (uint8_t)(rows[r] >> 16);
            ikm[r * 4 + 2] = (uint8_t)(rows[r] >> 8);
            ikm[r * 4 + 3] = (uint8_t)rows[r];
        }

        uint8_t derived[SHA256_DIGEST_LEN];
        int rc = hkdf(NULL, 0, ikm, sizeof(ikm), (const uint8_t *)purpose, strlen(purpose),
                      derived, sizeof(derived));

        memset(ikm, 0, sizeof(ikm));
        memset(rows, 0, sizeof(rows));

        if (rc < 0) {
            fprintf(stderr, "unlock: key derivation failed\n");
            return 1;
        }

        for (unsigned i = 0; i < sizeof(derived); i++)
            sprintf(hex + i * 2, "%02x", derived[i]);

        memset(derived, 0, sizeof(derived));
    }

    char out[OTP_HEX_LEN + 2];
    memcpy(out, hex, OTP_HEX_LEN);
    out[OTP_HEX_LEN] = '\n';

    int rc = write(STDOUT_FILENO, out, OTP_HEX_LEN + 1);

    // Do not leave the key in this process's memory any longer than the write.
    memset(hex, 0, sizeof(hex));
    memset(out, 0, sizeof(out));

    if (rc < 0) {
        perror("unlock: writing key");
        return 1;
    }

    return 0;
}
