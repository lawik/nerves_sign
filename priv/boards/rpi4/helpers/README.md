# RPi4/CM4 key helpers

cryptinit resolves an encryption key by running a `cmd:` helper that prints 64
hex characters on stdout. For RPi4/CM4 the key is read from the customer OTP
rows via the VideoCore mailbox (`/dev/vcio`).

We do not vendor the helper source here. Use the upstream reference and build it
static against the musl Nerves toolchain:

- Reference: `nerves_cryptinit`, `examples/pi5-otp/` (`unlock.c` works on Pi4/CM4
  too — it reads `MBOX_TAG_GET_CUSTOMER_OTP`).
- Build it static (`CC=aarch64-nerves-linux-musl-gcc CFLAGS="-Os -static"`),
  install at `/usr/sbin/unlock` in the CPIO, and set
  `rootfs_key = cmd:/usr/sbin/unlock` in `initramfs.conf`.

## Helper contract (from cryptinit)

- Input: none (figures out state from the device).
- Output: 64 hex chars on stdout (256-bit key); whitespace trimmed.
- Exit 0 on success; non-zero is fatal (cryptinit panics — correct, since the
  rootfs can't unlock).

## First-boot bootstrap

First-boot encrypt-in-place is a separate `cmd:` helper
(`bootstrap-or-derive`), not part of the init. On an unprovisioned device it
generates the key, sets up dm-crypt on the destination, copies the plaintext
rootfs through it, wipes the source last, persists the key to OTP, then prints
the key; on later boots it just reads OTP and prints. The state machine must be
idempotent and power-loss safe (wipe the source only after the destination
verifies mountable). nerves_sign will ship a board template for this; the key
source is the OTP read above.
