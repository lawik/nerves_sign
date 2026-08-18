// SPDX-License-Identifier: Apache-2.0
//
// bootstrap-or-derive: cryptinit's `cmd:` key helper for a device that may not
// be provisioned yet.
//
//     rootfs_key = cmd:/usr/sbin/bootstrap-or-derive /dev/mmcblk0p2 /dev/mmcblk0p3
//
// On a provisioned, already-encrypted device this prints the key and exits,
// which is all cryptinit ever sees. On a fresh one it generates a key, burns
// it into the device private key rows, converts the plaintext rootfs in place, and
// then prints the same key. cryptinit does not know the difference; it asked
// for a key and got one, possibly slowly.
//
// The arguments are the rootfs partition and a same-sized staging partition —
// the spare A/B rootfs slot. Both belong to the firmware project's layout, so
// they are passed in rather than compiled in.
//
// Deliberately not automatic about the dangerous half: it will burn OTP on a
// blank device, because that is the whole point of first boot, but it will
// never write over a key that is already there and never touch a rootfs it
// cannot account for.

#include "blockdev.h"
#include "bootstrap.h"
#include "kdf.h"
#include "otp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--purpose STRING] [--raw] <rootfs-device> <staging-device> [cipher]\n"
            "\n"
            "  rootfs-device   the partition cryptinit will mount\n"
            "  staging-device  the spare A/B rootfs slot, same size\n"
            "  cipher          dm-crypt cipher (default aes-xts-plain64); must\n"
            "                  match rootfs_cipher in initramfs.conf\n"
            "  --purpose STR   HKDF info string (default \"rootfs\"); must match\n"
            "                  whatever unlock uses for the same volume\n"
            "  --raw           no derivation, for devices provisioned before it\n",
            argv0);
    return 1;
}

// Derive the volume key from the OTP secret, or pass it through for --raw.
static int derive(const uint32_t *rows, const char *purpose, int raw, char *hex_out)
{
    if (raw) {
        otp_format_hex(rows, hex_out);
        return 0;
    }

    uint8_t ikm[OTP_ROW_COUNT * 4];
    for (unsigned r = 0; r < OTP_ROW_COUNT; r++) {
        ikm[r * 4] = (uint8_t)(rows[r] >> 24);
        ikm[r * 4 + 1] = (uint8_t)(rows[r] >> 16);
        ikm[r * 4 + 2] = (uint8_t)(rows[r] >> 8);
        ikm[r * 4 + 3] = (uint8_t)rows[r];
    }

    uint8_t out[SHA256_DIGEST_LEN];
    int rc = hkdf(NULL, 0, ikm, sizeof(ikm), (const uint8_t *)purpose, strlen(purpose), out,
                  sizeof(out));
    memset(ikm, 0, sizeof(ikm));

    if (rc < 0)
        return -1;

    for (unsigned i = 0; i < sizeof(out); i++)
        sprintf(hex_out + i * 2, "%02x", out[i]);

    memset(out, 0, sizeof(out));
    return 0;
}

// Read the device key, generating and burning one if this device has none.
static int resolve_key(const char *purpose, int raw, char *hex_out)
{
    uint32_t rows[OTP_ROW_COUNT];

    if (otp_read(rows) < 0) {
        perror("bootstrap: reading the device private key");
        return -1;
    }

    if (!otp_blank(rows))
        return derive(rows, purpose, raw, hex_out);

    fprintf(stderr, "bootstrap: private key rows are blank; generating a device key\n");

    if (otp_generate(rows) < 0) {
        perror("bootstrap: generating a key");
        return -1;
    }

    // Burn before converting. If the burn fails the device is untouched; if it
    // succeeds but conversion is interrupted, the next boot reads the same key
    // back and resumes. The other order would encrypt with a key that might
    // never make it into OTP, which is unrecoverable.
    if (otp_write(rows) < 0) {
        perror("bootstrap: burning the key into OTP");
        return -1;
    }

    // The one irreversible event in the whole flow; it gets a line in the log.
    // otp_write has already read the rows back and verified them.
    fprintf(stderr, "bootstrap: key burned into OTP and verified by readback\n");

    return derive(rows, purpose, raw, hex_out);
}

int main(int argc, char **argv)
{
    const char *purpose = "rootfs";
    int raw = 0;
    const char *positional[3] = {NULL, NULL, NULL};
    int n = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--raw") == 0)
            raw = 1;
        else if (strcmp(argv[i], "--purpose") == 0 && i + 1 < argc)
            purpose = argv[++i];
        else if (n < 3)
            positional[n++] = argv[i];
        else
            return usage(argv[0]);
    }

    if (n < 2)
        return usage(argv[0]);

    struct bootstrap_config cfg = {
        .rootfs_device = positional[0],
        .staging_device = positional[1],
        .cipher = positional[2] ? positional[2] : "aes-xts-plain64",
    };

    char key_hex[OTP_HEX_LEN + 1];

    if (resolve_key(purpose, raw, key_hex) < 0)
        return 1;

    if (bootstrap_run(&cfg, key_hex) < 0) {
        perror("bootstrap: converting the rootfs");
        return 1;
    }

    // cryptinit's cmd: contract: the key as hex on stdout, exit 0.
    char out[OTP_HEX_LEN + 2];
    memcpy(out, key_hex, OTP_HEX_LEN);
    out[OTP_HEX_LEN] = '\n';

    if (write(STDOUT_FILENO, out, OTP_HEX_LEN + 1) < 0) {
        perror("bootstrap: writing the key");
        return 1;
    }

    return 0;
}
