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
{:nerves_sign, github: "lawik/nerves_sign", runtime: false}
```

```
mix nerves_sign.gen.rpi4
```

then wire the printed `config :nerves_sign, board: :rpi4` and
`post_processing_script` into your target config. The generated
`config/rpi4/*` files are yours to edit.

See `PLAN.md` for architecture, build flow, and milestones.
