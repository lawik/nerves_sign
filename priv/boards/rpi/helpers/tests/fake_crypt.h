// SPDX-License-Identifier: Apache-2.0

#ifndef FAKE_CRYPT_H
#define FAKE_CRYPT_H

#include <stdint.h>

extern unsigned fake_crypt_encrypt_calls;

void fake_crypt_reset(void);
void fake_crypt_fail_after(uint64_t bytes);

#endif
