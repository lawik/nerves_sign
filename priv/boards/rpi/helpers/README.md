# Raspberry Pi key helpers

cryptinit resolves an encryption key by running a `cmd:` helper that prints 64
hex characters on stdout. On a Raspberry Pi the key comes from the device
private key rows in OTP, read via the VideoCore mailbox (`/dev/vcio`).

## Which OTP area, and why

There are two candidates, and they are not interchangeable:

| area | tags | `vcgencmd otp_dump` |
|---|---|---|
| customer OTP | `0x00030021` / `0x00038021` | **visible** |
| device private key | `0x00030081` / `0x00038081` | not visible |

We use the **private key** area. It is what `rpi-otp-private-key` writes, and
keeping the disk key out of `otp_dump` is the point. Note that cryptinit's
`examples/pi5-otp/` helper reads customer OTP — it is illustrative, and a key
burned into one area is invisible from the other, so mixing them looks exactly
like an unprovisioned device.

This lives in `priv/boards/rpi/` rather than under a board because the mailbox
is a family interface: any Pi that exposes customer OTP uses the same helper.
Board-specific helpers, if one ever needs them, belong in that board's priv dir.

## Default: `unlock.c`

nerves_sign ships `unlock.c` here as the default helper for every Pi board.
It's built static against the musl Nerves toolchain, installed at
`/usr/sbin/unlock`, and wired with `rootfs_key = cmd:/usr/sbin/unlock` in
`initramfs.conf`.

## Layout

- `unlock.c` — reads the key, prints hex. What cryptinit execs.
- `otp.c` / `otp.h` — customer OTP rows: read, write, generate.
- `mailbox.c` / `mailbox.h` — the VideoCore property interface, isolated so
  everything above it can be tested on a build host.
- `bootstrap.c` / `bootstrap.h` — first-boot conversion of a plaintext rootfs
  to an encrypted one, staged through the spare A/B slot.
- `blockdev.c` / `blockdev.h` — sizes, copies, durability. No `dd`.
- `crypt.h` — the dm-crypt seam. The real backend is not written yet; the
  tests link a reversible stand-in.
- `tests/` — host tests with an in-memory mailbox and a stand-in cipher.
  `make test`.

Style follows nerves_cryptinit: static musl, syscalls rather than subprocesses,
small. There is no shell in the initramfs to shell out to.

## Burning a key

`otp_write()` refuses unless the rows are blank, and reads back to confirm.
These bits are one-time programmable — a bit burned to 1 never returns to 0 —
so a second write ORs into the existing key and permanently destroys the
device's ability to decrypt its own rootfs. `unlock` itself only ever reads.

## First-boot conversion

`bootstrap.c` turns a plaintext rootfs into an encrypted one on first boot and
is meant to run as cryptinit's `cmd:` helper, so the init never learns a
conversion happened.

It works because dm-verity sits *on top* of dm-crypt: encrypting the whole
partition, filesystem and appended hash tree together, leaves the plaintext
verity sees byte-identical. The root hash does not change, so the signed
cmdline stays valid and nothing needs re-signing.

The conversion stages through the spare A/B rootfs slot rather than RAM, which
is what makes every interruption resumable:

    plaintext        -> encrypt rootfs into the staging slot, verify, write back
    staged           -> a previous run died mid-write-back; finish it
    done             -> hand over the key
    anything else    -> refuse to write

"Converted" means the squashfs magic decrypts at the start *and* the verity
superblock decrypts at the hash offset. Checking only the magic would call a
device converted after the first block had been written back, and hand a key
for a rootfs that then fails verity.

**Not finished:** `crypt.h` has no on-device backend yet, so this does not run
on hardware. The state machine is tested on a host against a reversible
stand-in, since power loss between stages is not reachable any other way.

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
