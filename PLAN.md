# nerves_sign — plan

Compile-time Nerves tooling for secure boot. One library, Nerves-only, no
wider use cases. It replaces `ex_verity`. We do not preserve any of the old
structure; we lift the pieces that still apply (RPi4) and drop the rest.

## The two-repo world

- **nerves_cryptinit** (Frank Hunleth, public, upstream): the runtime init. A
  tiny static-musl C `init` that does dm-verity (mandatory) and optional
  dm-crypt via raw device-mapper ioctls, then `switch_root`s to the real init.
  We **consume** it (build it from source), we do not vendor or fork it.
- **nerves_sign** (this repo): the compile-time half. Generates the dm-verity
  hash tree, builds the initramfs CPIO (cryptinit + board key helper +
  `/etc/initramfs.conf`), assembles and signs `boot.img`/`boot.sig`, and puts
  the verity root hash on the signed kernel cmdline.

There is no `verity_initramfs` repo and no Buildroot. The old initramfs build
existed only to assemble a glibc userland with cryptsetup/veritysetup/busybox;
cryptinit (static, in-kernel dm targets) deletes that reason. The CPIO is now
`init` + one helper + a config file + empty mountpoints.

Standing precondition nerves_sign cannot satisfy: the **kernel** must have
`CONFIG_DM_VERITY`, `CONFIG_DM_CRYPT`, and the needed crypto (`CRYPTO_SHA256`
for verity; `CRYPTO_AES` + the cipher mode for crypt) built in `=y` (no module
loading in the initramfs). That lives in the Nerves system, not here. Each
board entry documents the required kernel config.

## Responsibilities

1. **dm-verity hash tree** — `veritysetup format` appends the hash tree to the
   rootfs at a 4096-aligned offset; returns the root hash. (Lifted from
   ex_verity `DmVerity`; unchanged — cryptinit reads this exact layout.)
2. **Root hash onto the signed cmdline** — write `verity_roothash=<hash>` into
   the `cmdline.txt` that goes inside `boot.img`. This is the trust anchor.
   (New. Replaces ex_verity stashing `root_hash.txt`/`verity_offset.txt` files
   in boot.img; cryptinit takes the hash from the cmdline and derives the
   offset from the filesystem superblock.)
3. **Initramfs build** — compile cryptinit `init` and the board key helper(s)
   with the **musl** Nerves toolchain (static), assemble a CPIO
   (`/init`, `/usr/sbin/<helper>`, `/etc/initramfs.conf`, empty `/dev /proc
   /sys /mnt`), gzip it.
4. **boot.img** — pack kernel + initramfs.cpio.gz + dtbs/overlays + inner
   config.txt/cmdline.txt into a FAT image via fwup. (Lifted/renamed from
   ex_verity `Rpi4SecureBoot` + `boot_fwup.conf`.) Optionally gzip the kernel
   (`Image` -> `Image.gz`) — supported but not required once the initramfs is
   tiny; off by default, board-configurable.
5. **Signing** — RSA-2048 SHA-256 over boot.img in the RPi bootloader format ->
   `boot.sig`. (Lifted from ex_verity `sign_image`.)
6. **Board abstraction** — a `NervesSign.Board` behaviour. Each board supplies:
   fwup config for boot.img, dtb/overlay list, the key-helper source, the
   default cipher, and the required kernel CONFIG. Selected by
   `config :nerves_sign, board: :rpi4` (decoupled from the user's target name,
   since one project may have several rpi4-derived targets).
7. **Scaffolding** — `mix nerves_sign.gen.<board>` copies the project-owned
   configs (fwup.conf, config.txt, cmdline.txt, initramfs.conf) into the
   firmware project. The developer owns and edits these; no fork of nerves_sign
   needed to adjust a system.
8. **Toolchain acquisition** — depend on the musl Nerves toolchain hex package
   (e.g. `nerves_toolchain_aarch64_nerves_linux_musl`). Default to the musl
   counterpart of the project's own toolchain version; allow override via
   `config :nerves_sign, toolchain: ...`.
9. **Runtime convenience API (optional, separate surface)** — small Elixir
   helpers for OTP access on supported RPi boards (provisioning/inspection from
   the running system). This is NOT on the boot path — the C `unlock` helper is
   what runs in the initramfs. Ship later; keep the boundary clear.

## Module layout

```
lib/nerves_sign.ex                  top-level API + run/1 orchestration
lib/nerves_sign/post_process.ex     mix firmware post_processing entrypoint
lib/nerves_sign/dm_verity.ex        veritysetup format (lifted)
lib/nerves_sign/boot_image.ex       boot.img assemble + sign (lifted)
lib/nerves_sign/cmdline.ex          inject verity_roothash= into cmdline.txt
lib/nerves_sign/initramfs.ex        build cryptinit + helper, assemble CPIO
lib/nerves_sign/cryptinit.ex        resolve + build the cryptinit init binary
lib/nerves_sign/toolchain.ex        resolve/acquire the musl toolchain ($CC)
lib/nerves_sign/board.ex            behaviour
lib/nerves_sign/boards/rpi4.ex      RPi4/CM4 board impl
lib/mix/tasks/nerves_sign.gen.rpi4.ex  scaffold project configs

priv/boards/rpi4/
  boot_fwup.conf      inner boot.img fwup (lifted)
  config.txt          inner RPi config (lifted, kernel/initramfs lines kept)
  cmdline.txt         inner cmdline template (root=/rootfstype=/init=, hash injected)
  initramfs.conf      cryptinit config (rootfs_key = cmd:/usr/sbin/unlock, etc.)
  helpers/unlock.c    CM4/Pi4 OTP key helper (lifted from cryptinit pi5-otp)
  helpers/Makefile
```

## Build flow (where each thing runs)

Two phases, split to dodge the dep-compile config-visibility + cache problem.

**Compile phase (elixir_make in the nerves_sign dep):** build only the
board-agnostic cryptinit `init`. No board needed, caches cleanly. Uses the musl
toolchain `$CC` with `-static`.

**Post-processing phase (`mix firmware`, runs in the *parent* app context):**
here `Application.fetch_env!(:nerves_sign, :board)` and `Mix.target()` are
reliable and it re-runs every build. Do everything board-specific here:

1. Build the board key helper(s) (musl `$CC`, static).
2. `veritysetup format` the rootfs -> root hash. (`DmVerity`)
3. Inject `verity_roothash=<hash>` into the inner cmdline.txt. (`Cmdline`)
4. Assemble the CPIO: cryptinit `init` + helper + `initramfs.conf` + dirs ->
   `initramfs.cpio.gz`. (`Initramfs`)
5. (optional) gzip the kernel.
6. fwup-build `boot.img` from kernel(.gz) + initramfs + dtbs + inner txts.
   (`BootImage`)
7. Sign -> `boot.sig`. (`BootImage`)
8. Copy outer config.txt/cmdline.txt for the boot partition.

Wired via the standard Nerves hook the gen task sets up:

```elixir
config :nerves, :firmware,
  post_processing_script: Path.expand("priv/nerves_sign/post_process")
```

(The script just calls `NervesSign.PostProcess.run/1`.)

Why not build the helper under elixir_make too: Mix only re-runs Elixir
compiles on `compile_env` change, never the elixir_make C build, so a board
flip would ship a stale binary. Building board-specific C in post-process (and
keying artifacts by board) avoids it.

## Boot-chain contract (what changes vs ex_verity)

- Inner `cmdline.txt` gains `verity_roothash=<hash>` (injected at build) and
  sets `root=`, `rootfstype=`, `init=` (the real init cryptinit execs). The
  kernel runs the CPIO `/init` = cryptinit.
- The rootfs hash tree is appended after the squashfs at 4096 (DmVerity) —
  exactly what cryptinit's `fs.c` expects, so no offset file is shipped.
- Encryption (optional): `rootfs_key = cmd:/usr/sbin/unlock` in
  `initramfs.conf`. The cipher is **configurable** — cryptinit reads
  `rootfs_cipher`/`data_cipher` from `initramfs.conf` and passes the string
  straight to the dm-crypt table (default `aes-xts-plain64` only when unset).
  The library default is `aes-xts-plain64`; projects with already-provisioned
  devices override per volume (`config :nerves_sign, rootfs_cipher:
  "aes-cbc-plain"`) — that legacy choice lives in the project, never in the
  library. The exact cipher string must match in three places: `initramfs.conf`
  (runtime), the offline rootfs encryption in the outer fwup, and the kernel
  (`CRYPTO_XTS=y`/`CRYPTO_CBC=y`). `NervesSign.Board.cipher/2` resolves
  config-override-then-board-default.
- First-boot / encrypt-in-place is NOT in the init. It's a userspace
  `cmd:`-style helper (`bootstrap-or-derive`) the board can ship; the state
  machine pattern (copy -> verify-mountable -> wipe source last, idempotent,
  power-loss safe) is lifted in spirit from the zipabox2 `try_bootstrap`. Only
  the state machine is reused; key source is RPi OTP (the `unlock` mailbox
  read), not zipabox's salt+serial/ATECC.

## What we lift from ex_verity (RPi4 only)

- `DmVerity.generate_tree!` -> `NervesSign.DmVerity` (verbatim logic).
- `Rpi4SecureBoot` fwup create/apply + `sign_image` + `copy_outer_txts!` ->
  `NervesSign.BootImage`.
- `priv/templates/rpi4/{boot_fwup.conf,config.txt,cmdline.txt}` and the gen
  task -> `priv/boards/rpi4/*` and `Mix.Tasks.NervesSign.Gen.Rpi4`, adapted:
  drop the loose `kernel8.img`/`start4.elf`/dtb writes from the boot partition
  (secure boot only needs boot.img + boot.sig + tiny outer txts), default
  `BOOT_A_PART_COUNT` back to the stock Nerves size, and switch the init from
  the shell `init_sh` / old verity_init to cryptinit.

What we drop: the entire `priv/initramfs` buildroot tree, the home-grown
`verity_init`/`rpi_otp_key`/`nerves_key` packages, the shell `init_sh`, the
enlarged boot partition, and the loose-file boot layout.

## Preflight: where the board seam is

Validation before signing splits in two, and the split is the thing to keep
straight when a second board arrives:

- **The cryptinit contract** (`NervesSign.Preflight.check_cmdline!/1`) — what
  the kernel cmdline must carry for the init we package to work: `root=`
  naming the *backing* device (cryptinit creates the dm nodes itself), `ro`,
  and the injected `verity_roothash=`. These come from cryptinit's `main.c`,
  so they hold for every board that boots it. Shared, always runs first.
- **The boot firmware contract** (`c:NervesSign.Board.preflight!/1`) — how a
  ROM or firmware finds the kernel, initramfs and cmdline. Nothing here
  generalizes: RPi parses `config.txt` out of the FAT boot image
  (`NervesSign.Boards.RPi4.Preflight`), while an i.MX HAB/TrustZone chain
  validates a signed container and has no `config.txt` at all. Required
  callback, not optional — for a secure boot tool, "this board has nothing to
  validate" should be a sentence someone wrote on purpose.

`preflight!/1` takes the resolved build context as a **map** so boards read the
keys they need and new keys can be added without breaking existing boards.
`NervesSign.Fwup.fat_files/1` sits between the two: fwup-generic rather than
RPi-specific, useful to any board whose boot image is a FAT built by fwup, and
irrelevant to one whose image is a raw signed blob.

Still RPi4-shaped and *not* yet behind the seam, for whenever a second board
lands: the `rpi4_secure_boot` config key, the `config/rpi4/*` default paths in
`NervesSign.PostProcess`, and `NervesSign.BootImage` (the RPi bootloader
signature format and the outer-txt copy).

## Milestones

1. **Skeleton + lift** (done): mix project, modules with lifted
   DmVerity/BootImage logic, rpi4 priv assets, gen task, this plan.
2. **Toolchain + cryptinit build** (done, measured 2026-06-15): built with the
   musl Nerves toolchain `aarch64-nerves-linux-musl` (GCC 14.2, from the
   v14.2.0 release). cryptinit `init` static = **139 KB (67 KB stripped)**;
   our `unlock.c` static = **128 KB (67 KB stripped)**. Both link clean static.
3. **Initramfs assembly** (done, measured): CPIO (init + unlock +
   initramfs.conf + dirs) gzips to **~49 KB** (vs the old 11.4 MB). With a
   **raw, uncompressed 12 MB kernel**, boot.img content = **14.63 MiB**, fits
   the default **18.86 MiB** boot partition (nested boot.img + sig + outer txts)
   with **~2.9 MiB free**. Conclusion: **gzipping the kernel is unnecessary**;
   keep the kernel raw, ship the stock boot-partition size.
4. **Cmdline + boot.img + sign**: inject `verity_roothash=`, build and sign
   boot.img with the new minimal layout.
5. **End-to-end on a stock-ish RPi4 system** (entryfy_system_cm4 once cleaned):
   QEMU and/or device boot.
6. **Board behaviour generalization** + **bootstrap helper** + **OTP Elixir
   convenience API**.

## Open decisions

- ~~Cipher~~ (resolved): configurable per volume via `initramfs.conf`
  (`rootfs_cipher`/`data_cipher`), library default `aes-xts-plain64`, project
  override for legacy devices (entryfy keeps `aes-cbc-plain` in its own config,
  not the library). cryptinit already supports this; no init change needed.
- Key helper: nerves_sign ships a default RPi `unlock.c` (OTP via `/dev/vcio`,
  shared rpi4/cm4); projects override the source with
  `config :nerves_sign, key_helper_source:` (e.g. HKDF, or a first-boot
  bootstrap state machine). Product-specific helpers live in the project.
- Whether to gzip the kernel by default (probably no, once the initramfs is
  ~hundreds of KB — a raw kernel fits the default partition).
- Whether the cryptinit source is a git dep (pinned ref) or a published hex
  package once it stabilizes.
