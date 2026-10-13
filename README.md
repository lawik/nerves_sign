# nerves_sign

Compile-time Nerves tooling for secure boot. It generates the dm-verity hash
tree, builds and packages a minimal initramfs around
[nerves_cryptinit](https://github.com/fhunleth/nerves_cryptinit), assembles and
signs `boot.img`/`boot.sig`, and puts the verity root hash on the signed kernel
cmdline.

**Status: early. Design in `PLAN.md`. Replaces `ex_verity`.**

## The shape

Two pieces:

- **nerves_cryptinit** (upstream): the runtime init — a tiny static-musl C
  `init` doing dm-verity (+ optional dm-crypt) via raw device-mapper ioctls,
  then `switch_root`. We build it from source and package it; we don't fork it.
- **nerves_sign** (this repo): the build-time half — hash tree, initramfs CPIO,
  boot.img assembly + signing, root hash onto the cmdline.

No Buildroot, no separate initramfs repo. The initramfs is just the static
`init` + a board key helper + `/etc/initramfs.conf`.

Precondition nerves_sign can't provide: the **kernel** must have dm-verity,
dm-crypt, and the needed crypto built in (`=y`); see
`NervesSign.Boards.RPi4.required_kernel_config/0`.

## Usage (target)

```elixir
# mix.exs
{:nerves_sign, github: "underjord/nerves_sign", runtime: false}
```

```
mix nerves_sign.gen.rpi4
```

then wire the printed `config :nerves_sign, board: :rpi4` and
`post_processing_script` into your target config. The generated
`config/rpi4/*` files are yours to edit.

See `PLAN.md` for architecture, build flow, and milestones.

## Tests

```
mix test                      # unit tier, plus integration when it can
mix test --include integration # force the integration tier
mix test --exclude integration # unit tier only
```

Two tiers. The **unit** tier is pure and always runs: cmdline rendering, the
preflight checks, board/toolchain/path resolution, and the hand-written newc
CPIO carrying `/dev/console` and `/dev/kmsg`.

The **integration** tier runs the real pipeline against a fixture system and
uses [bodge_rpiboottest](https://github.com/lawik/bodge_rpiboottest) — a test
double for the RPi4 EEPROM bootloader — as the oracle for signing, tamper
refusal, wrong-key refusal and the tryboot A/B cycle. It needs `veritysetup`,
`mksquashfs`, `fwup`, `mtools`, `cpio`, `make`, and the musl cross-toolchain
(fetched on first use, or point `NERVES_SIGN_TEST_TOOLCHAIN_BIN` at a cached
`bin/`). It opts itself in once the toolchain is cached; `--include
integration` forces it.

A third tier in `test/integration/qemu_boot_test.exs` boots the signed image on
QEMU `raspi4b` for real: bodge picks the partition and verifies the signature,
then the kernel, initramfs and cmdline it extracted from the *signed* image are
handed to QEMU. Success means cryptinit opened dm-verity with the root hash off
the signed cmdline, mounted through it, and switch_rooted.

It needs a built Nerves system whose kernel has `CONFIG_DM_VERITY`,
`CONFIG_DM_CRYPT` and the crypto `=y`, plus QEMU 9.0+ for the `raspi4b`
machine. Any Nerves rpi4/cm4 system with those options works — the artifacts
a project has already built are enough:

```
NERVES_SIGN_TEST_SYSTEM=/path/to/project/.nerves/artifacts/<system>-portable-<ver> \
  NERVES_SIGN_TEST_TOOLCHAIN_BIN=/path/to/musl/bin \
  mix test --include integration test/integration/qemu_boot_test.exs
```

It runs in about four seconds.
