# RPi4/CM4 key helpers

cryptinit resolves an encryption key by running a `cmd:` helper that prints 64
hex characters on stdout. For RPi4/CM4 the key comes from the customer OTP rows
read via the VideoCore mailbox (`/dev/vcio`).

## Default: `unlock.c`

nerves_sign ships `unlock.c` here as the default helper for both rpi4 and cm4.
It's built static against the musl Nerves toolchain, installed at
`/usr/sbin/unlock`, and wired with `rootfs_key = cmd:/usr/sbin/unlock` in
`initramfs.conf`.

## Using your own helper

Point nerves_sign at an alternate source instead of the default:

```elixir
config :nerves_sign, key_helper_source: "priv/secure_boot/unlock.c"
```

Reasons you'd override:
- per-partition key derivation (HKDF over the OTP bytes, taking a `purpose` arg),
- a first-boot **bootstrap** helper that provisions an unprovisioned device
  (generate key -> dm-crypt the destination -> copy plaintext rootfs through it
  -> wipe source last -> persist key to OTP -> print key), idempotent and
  power-loss safe. The bare `unlock.c` reports an empty OTP as an error rather
  than provisioning.

## Helper contract (from cryptinit)

- Input: none (figures out state from the device).
- Output: 64 hex chars on stdout; whitespace trimmed.
- Exit 0 on success; non-zero is fatal (cryptinit panics).

## Project-specific helpers don't live here

Anything tied to a particular product's existing scheme (e.g. a legacy
`aes-cbc-plain` first-boot conversion) belongs in that firmware project and is
referenced via `key_helper_source`, not added to nerves_sign.
