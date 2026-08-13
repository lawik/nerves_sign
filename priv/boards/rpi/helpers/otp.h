// SPDX-License-Identifier: Apache-2.0
//
// Raspberry Pi customer OTP rows: the 256-bit per-device secret the encrypted
// rootfs is keyed from.
//
// These rows are one-time programmable. A bit that has been burned to 1 can
// never go back to 0, so a wrong write is permanent and the device is done.
// Every write path here refuses to touch a row that is already non-zero.

#ifndef OTP_H
#define OTP_H

#include <stdint.h>

// 8 rows x 32 bits = 256-bit key.
#define OTP_ROW_COUNT 8
#define OTP_FIRST_ROW 0

// Hex characters for the whole key, without a NUL.
#define OTP_HEX_LEN (OTP_ROW_COUNT * 8)

// Read the customer OTP rows. Returns 0 on success, -1 on failure.
int otp_read(uint32_t rows[OTP_ROW_COUNT]);

// Write the customer OTP rows. Refuses (-1, errno EEXIST) unless the device is
// currently blank, because burning over a programmed row destroys the device's
// key permanently. Reads back and compares before returning success.
int otp_write(const uint32_t rows[OTP_ROW_COUNT]);

// True when every row is zero: an unprovisioned device.
int otp_blank(const uint32_t rows[OTP_ROW_COUNT]);

// Fill `rows` with cryptographically secure random data from getrandom(2).
// Returns 0 on success, -1 on failure. Never falls back to a weaker source.
int otp_generate(uint32_t rows[OTP_ROW_COUNT]);

// Format rows as lowercase hex into `out`, which must hold OTP_HEX_LEN + 1.
void otp_format_hex(const uint32_t rows[OTP_ROW_COUNT], char *out);

#endif
