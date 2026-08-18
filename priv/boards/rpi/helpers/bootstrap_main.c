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
#include "otp.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s <rootfs-device> <staging-device> [cipher]\n"
            "\n"
            "  rootfs-device   the partition cryptinit will mount\n"
            "  staging-device  the spare A/B rootfs slot, same size\n"
            "  cipher          dm-crypt cipher (default aes-xts-plain64); must\n"
            "                  match rootfs_cipher in initramfs.conf\n",
            argv0);
    return 1;
}

// Read the device key, generating and burning one if this device has none.
static int resolve_key(char *hex_out)
{
    uint32_t rows[OTP_ROW_COUNT];

    if (otp_read(rows) < 0) {
        perror("bootstrap: reading the device private key");
        return -1;
    }

    if (!otp_blank(rows)) {
        otp_format_hex(rows, hex_out);
        return 0;
    }

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

    otp_format_hex(rows, hex_out);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4)
        return usage(argv[0]);

    struct bootstrap_config cfg = {
        .rootfs_device = argv[1],
        .staging_device = argv[2],
        .cipher = argc == 4 ? argv[3] : "aes-xts-plain64",
    };

    char key_hex[OTP_HEX_LEN + 1];

    if (resolve_key(key_hex) < 0)
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
