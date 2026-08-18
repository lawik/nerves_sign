defmodule NervesSign.Integration.SecureBootTest do
  @moduledoc """
  Full-pipeline integration test.

  `NervesSign.PostProcess` runs against a fixture system (fake kernel/dtbs,
  tiny mksquashfs rootfs, throwaway RSA key), producing the real cryptinit
  initramfs and a signed `boot.img`/`boot.sig`. BodgeRPiBootTest, the RPi4 EEPROM
  bootloader test double, is the oracle: signed boot, tamper refusal, wrong
  OTP key refusal, and the tryboot A/B trial + commit cycle, all against a
  provisioned A/B disk image.

  Run with: `mix test --include integration`

  The musl toolchain is fetched by `NervesSign.Toolchain` unless
  `NERVES_SIGN_TEST_TOOLCHAIN_BIN` points at a cached toolchain `bin/` dir.
  """
  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag timeout: 300_000

  tools = ~w(veritysetup mksquashfs fwup mcopy mdir cpio gzip make)
  missing = Enum.reject(tools, &System.find_executable/1)

  if missing != [] do
    @moduletag skip: "missing host tools: #{Enum.join(missing, ", ")}"
  end

  unless File.dir?(Path.join(Mix.Project.deps_path(), "nerves_cryptinit/src")) do
    @moduletag skip: "nerves_cryptinit dep not fetched (run mix deps.get)"
  end

  @dtbs ~w(bcm2711-rpi-4-b.dtb bcm2711-rpi-400.dtb bcm2711-rpi-cm4.dtb ramoops.dtb)
  @overlays ~w(overlay_map.dtb vc4-kms-v3d.dtbo vc4-kms-v3d-pi4.dtbo dwc2.dtbo)

  @autoboot """
  [all]
  tryboot_a_b=1
  boot_partition=2
  [tryboot]
  boot_partition=3
  """

  setup_all do
    root = Path.join(System.tmp_dir!(), "ns_int_#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    sys = fixture_system!(root)
    app = fixture_app!(root)
    rootfs = fixture_rootfs!(root)

    key = Path.join(root, "key.pem")
    pub = Path.join(root, "key.pub.pem")
    :ok = BodgeRPiBootTest.generate_keys(key, pub)

    configure_nerves_sign!(sys, app, key)

    :ok = NervesSign.PostProcess.run(rootfs)

    images = Path.join(sys, "images")

    {:ok,
     root: root,
     images: images,
     boot_img: Path.join(images, "boot.img"),
     boot_sig: Path.join(images, "boot.sig"),
     key: key,
     pub: pub,
     rootfs: rootfs}
  end

  test "pipeline produced signed artifacts that cross-verify", c do
    assert File.exists?(c.boot_img)
    assert File.exists?(c.boot_sig)
    assert File.exists?(Path.join(c.images, "outer_config.txt"))
    assert File.exists?(Path.join(c.images, "outer_cmdline.txt"))

    # bodge_rpiboottest's verifier is byte-compatible with rpi-eeprom-digest, so
    # this checks nerves_sign's signature against an independent implementation.
    assert BodgeRPiBootTest.verify(c.boot_img, c.boot_sig, c.pub) == :ok

    # The verity root hash must ride the signed inner cmdline, on one line.
    cmdline = extract!(c, "cmdline.txt")
    assert cmdline =~ ~r/verity_roothash=[0-9a-f]{64}/
    refute String.trim(cmdline) =~ "\n"

    # The whole point of the cryptinit initramfs: boot.img fits the stock
    # 18.86 MiB Nerves boot partition.
    assert File.stat!(c.boot_img).size <= 38_630 * 512
  end

  test "boot.img carries every file its config.txt points at", c do
    listing = mdir!(c.boot_img)

    # Not just "it built": the firmware resolves these names at boot, and a
    # missing initramfs boots straight past dm-verity without complaining.
    for name <- ~w(Image rootfs.cpio.gz config.txt cmdline.txt) do
      assert name in listing, "#{name} missing from boot.img (have: #{inspect(listing)})"
    end

    # Overlays go in overlays/ to match mainline nerves_system_rpi4, and
    # ramoops is renamed from .dtb to .dtbo on the way in.
    for name <- ~w(overlays/overlay_map.dtb overlays/vc4-kms-v3d.dtbo overlays/ramoops.dtbo) do
      assert name in listing, "#{name} missing from boot.img"
    end
  end

  test "the initramfs inside the signed image is the one that was built", c do
    cpio_gz = Path.join(c.root, "extracted.cpio.gz")
    {_, 0} = System.cmd("mcopy", ["-n", "-i", c.boot_img, "::rootfs.cpio.gz", cpio_gz])

    # Two concatenated archives: the synthesized device nodes, then the real
    # one. The kernel unpacks both; cpio stops at the first TRAILER, so each
    # member is listed separately.
    raw = cpio_gz |> File.read!() |> :zlib.gunzip()
    {nodes, main} = split_at_trailer(raw)

    # Without these cryptinit comes up with no console and logs nowhere.
    node_listing = cpio_list(c, nodes)
    assert node_listing =~ ~r/^c.*\s5,\s*1\s.*dev\/console$/m
    assert node_listing =~ ~r/^c.*\s1,\s*11\s.*dev\/kmsg$/m

    listing = cpio_list(c, main)
    assert listing =~ ~r/\sinit$/m
    assert listing =~ ~r/usr\/sbin\/unlock$/m

    # Both helpers ship: unlock reads an existing key, bootstrap-or-derive also
    # provisions a blank device and converts a plaintext rootfs on first boot.
    assert listing =~ ~r/usr\/sbin\/bootstrap-or-derive$/m
    # This fixture generates no initramfs.conf, which is how a verity-only
    # device is expressed: cryptinit treats the file as optional.
    refute listing =~ ~r/etc\/initramfs.conf$/m

    # /init is what the kernel execs, so it has to be executable.
    assert listing =~ ~r/^-rwxr-xr-x.*\sinit$/m
  end

  test "boot.img still has room for a kernel that grows", c do
    # The FAT is a fixed size, so asserting on the image's own size only
    # re-reads a define in boot_fwup.conf. What can actually break a build is
    # the content outgrowing it, which is the free space.
    {out, 0} = System.cmd("mdir", ["-i", c.boot_img, "::"], stderr_to_stdout: true)

    [_, free] = Regex.run(~r/([\d ]+) bytes free/, out)
    free = free |> String.replace(" ", "") |> String.to_integer()

    assert free > 1_000_000,
           "only #{div(free, 1024)} KiB free in boot.img; bump COUNT in boot_fwup.conf"
  end

  test "the outer txts are what the firmware needs to find boot.img", c do
    outer_config = File.read!(Path.join(c.images, "outer_config.txt"))

    # An unprovisioned dev board will not load the ramdisk without this.
    assert outer_config =~ "boot_ramdisk=1"

    # The outer cmdline is the untouched template: the signed inner one is what
    # the kernel actually gets, and that is where the trust anchor lives.
    outer_cmdline = File.read!(Path.join(c.images, "outer_cmdline.txt"))
    refute outer_cmdline =~ "verity_roothash="
  end

  test "unprovisioned device boots the signed image (unenforced)", c do
    disk = ab_disk!(c, "unprovisioned")
    r = BodgeRPiBootTest.boot(disk)
    assert r.success, BodgeRPiBootTest.Report.format(r)
    assert r.chosen.partition == 2
  end

  test "provisioned device verifies the signature and boots", c do
    disk = ab_disk!(c, "provisioned")
    :ok = BodgeRPiBootTest.provision(disk, c.pub)

    r = BodgeRPiBootTest.boot(disk)
    assert r.success, BodgeRPiBootTest.Report.format(r)
    assert r.chosen.partition == 2
    assert r.chosen.signed == 1
  end

  test "tampered boot.img is refused on a provisioned device", c do
    good = File.read!(c.boot_img)
    mid = div(byte_size(good), 2)
    <<pre::binary-size(mid), byte, post::binary>> = good
    tampered = <<pre::binary, rem(byte + 1, 256), post::binary>>

    disk = ab_disk!(c, "tampered", boot_img_a: tampered)
    :ok = BodgeRPiBootTest.provision(disk, c.pub)

    r = BodgeRPiBootTest.boot(disk)
    refute r.success, BodgeRPiBootTest.Report.format(r)
  end

  test "wrong OTP key refuses a correctly signed image", c do
    other_key = Path.join(c.root, "other.pem")
    other_pub = Path.join(c.root, "other.pub.pem")
    :ok = BodgeRPiBootTest.generate_keys(other_key, other_pub)

    disk = ab_disk!(c, "wrong_key")
    :ok = BodgeRPiBootTest.provision(disk, other_pub)

    r = BodgeRPiBootTest.boot(disk)
    refute r.success, BodgeRPiBootTest.Report.format(r)
  end

  test "tryboot trial then commit makes B the default", c do
    disk = ab_disk!(c, "tryboot")
    :ok = BodgeRPiBootTest.provision(disk, c.pub)

    r1 = BodgeRPiBootTest.boot(disk)
    assert r1.success, BodgeRPiBootTest.Report.format(r1)
    assert r1.chosen.partition == 2

    # Trial boot of the B slot: one-shot flag, cleared before the firmware
    # starts so a crash reverts to A.
    r2 = BodgeRPiBootTest.reboot(disk, "0 tryboot")
    assert r2.success, BodgeRPiBootTest.Report.format(r2)
    assert r2.chosen.partition == 3
    assert r2.chosen.tryboot == 1

    # Validate: swap the A/B roles in autoboot.txt.
    :ok = BodgeRPiBootTest.commit(disk)

    r3 = BodgeRPiBootTest.power_cycle(disk)
    assert r3.success, BodgeRPiBootTest.Report.format(r3)
    assert r3.chosen.partition == 3
    assert r3.chosen.tryboot == 0
  end

  # A newc entry is a 110-byte header plus the name, padded to 4 bytes. The
  # first archive ends after its TRAILER!!! entry; the rest is the next member.
  defp split_at_trailer(raw) do
    {pos, _} = :binary.match(raw, "TRAILER!!!")
    entry_end = pos + 11
    end_of_archive = entry_end + rem(4 - rem(entry_end, 4), 4)

    {binary_part(raw, 0, end_of_archive),
     binary_part(raw, end_of_archive, byte_size(raw) - end_of_archive)}
  end

  defp cpio_list(c, archive) do
    path = Path.join(c.root, "member_#{:erlang.phash2(archive)}.cpio")
    File.write!(path, archive)
    {listing, 0} = System.cmd("sh", ["-c", "cpio -tv < #{path} 2>&1"], stderr_to_stdout: true)
    listing
  end

  defp extract!(c, name) do
    out = Path.join(c.root, "extracted_#{Path.basename(name)}")
    {_, 0} = System.cmd("mcopy", ["-n", "-i", c.boot_img, "::#{name}", out])
    File.read!(out)
  end

  # Every file in the FAT image, with overlays/ entries as "overlays/<name>".
  defp mdir!(boot_img) do
    {root, 0} = System.cmd("mdir", ["-b", "-i", boot_img, "::"], stderr_to_stdout: true)

    {overlays, 0} =
      System.cmd("mdir", ["-b", "-i", boot_img, "::/overlays"], stderr_to_stdout: true)

    for line <- String.split(root <> overlays, "\n", trim: true) do
      line |> String.trim() |> String.trim_leading("::/")
    end
  end

  # -- fixtures ---------------------------------------------------------------

  defp fixture_system!(root) do
    sys = Path.join(root, "system")
    images = Path.join(sys, "images")
    overlays = Path.join(images, "rpi-firmware/overlays")
    File.mkdir_p!(overlays)

    for f <- @dtbs, do: File.write!(Path.join(images, f), filler(f, 4_096))
    File.write!(Path.join(images, "Image"), filler("Image", 1_000_000))
    File.write!(Path.join(images, "rpi-firmware/fixup4x.dat"), filler("fixup4x", 2_048))
    File.write!(Path.join(images, "rpi-firmware/start4x.elf"), filler("start4x", 100_000))
    for f <- @overlays, do: File.write!(Path.join(overlays, f), filler(f, 1_024))
    sys
  end

  defp fixture_app!(root) do
    app = Path.join(root, "app")
    conf = Path.join(app, "config/rpi4")
    File.mkdir_p!(conf)

    # root= names the partition holding the verity-formatted rootfs, not a dm
    # node: cryptinit reads this to find the backing device and creates /dev/dm-N
    # itself. `ro` because the verity device it hands us is read-only.
    File.write!(
      Path.join(conf, "cmdline.txt"),
      "console=ttyS0,115200 root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait quiet\n"
    )

    # boot_ramdisk=1 makes an unprovisioned (SIGNED_BOOT=0) bootloader load
    # boot.img; provisioned devices load it regardless. nerves_sign copies
    # this same file as the outer config.txt, so the ramdisk flag is required
    # here for dev boards to boot the ramdisk.
    #
    # The initramfs and cmdline lines are what make the firmware load cryptinit
    # and pass it the signed root hash. Without them this still builds and
    # signs, and boots straight past dm-verity.
    File.write!(Path.join(conf, "config.txt"), """
    arm_64bit=1
    boot_ramdisk=1
    kernel=Image
    initramfs rootfs.cpio.gz
    cmdline=cmdline.txt
    """)

    # boot_fwup.conf has no library fallback: it decides what goes inside the
    # signed image, so the project owns it. This is what the gen task copies.
    File.cp!(
      Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4", "boot_fwup.conf"]),
      Path.join(conf, "boot_fwup.conf")
    )

    app
  end

  defp fixture_rootfs!(root) do
    src = Path.join(root, "rootfs_src")
    File.mkdir_p!(src)
    File.write!(Path.join(src, "hello.txt"), "integration fixture\n")
    out = Path.join(root, "rootfs.squashfs")

    {_, 0} =
      System.cmd("mksquashfs", [src, out, "-quiet", "-no-progress"], stderr_to_stdout: true)

    out
  end

  defp filler(seed, size) do
    :sha256
    |> :crypto.hash(seed)
    |> :binary.copy(div(size, 32) + 1)
    |> binary_part(0, size)
  end

  defp configure_nerves_sign!(sys, app, key) do
    prev = Application.get_all_env(:nerves_sign)
    prev_app = System.get_env("NERVES_APP")

    Application.put_env(:nerves_sign, :board, :rpi4)
    Application.put_env(:nerves_sign, :system_path, sys)

    case System.get_env("NERVES_SIGN_TEST_TOOLCHAIN_BIN") do
      nil -> :ok
      bin -> Application.put_env(:nerves_sign, :toolchain, bin: bin)
    end

    Application.put_env(:nerves_sign, :rpi_secure_boot,
      private_key_path: key,
      cmdline_txt_path: Path.join(app, "config/rpi4/cmdline.txt"),
      config_txt_path: Path.join(app, "config/rpi4/config.txt")
    )

    System.put_env("NERVES_APP", app)

    on_exit(fn ->
      for {k, _} <- Application.get_all_env(:nerves_sign),
          do: Application.delete_env(:nerves_sign, k)

      for {k, v} <- prev, do: Application.put_env(:nerves_sign, k, v)

      if prev_app,
        do: System.put_env("NERVES_APP", prev_app),
        else: System.delete_env("NERVES_APP")
    end)
  end

  # -- disk building ----------------------------------------------------------

  # A/B disk in the canonical Nerves tryboot layout: partition 1 autoboot,
  # partitions 2/3 the boot.img slots. Slot A content is overridable so a
  # test can plant a tampered image.
  defp ab_disk!(c, name, opts \\ []) do
    dir = Path.join(c.root, name)
    File.mkdir_p!(dir)
    disk = Path.join(dir, "disk.img")

    sig = File.read!(c.boot_sig)

    # The real slot layout per the nerves_sign outer fwup template: signed
    # ramdisk plus the outer config/cmdline the firmware reads to load it.
    slot_common = %{
      "start4.elf" => "elf",
      "boot.sig" => sig,
      "config.txt" => File.read!(Path.join(c.images, "outer_config.txt")),
      "cmdline.txt" => File.read!(Path.join(c.images, "outer_cmdline.txt"))
    }

    slot_a =
      Map.put(slot_common, "boot.img", Keyword.get(opts, :boot_img_a, File.read!(c.boot_img)))

    slot_b = Map.put(slot_common, "boot.img", File.read!(c.boot_img))

    :ok =
      BodgeRPiBootTest.build_disk(disk, [
        %{
          size_mb: 8,
          files: %{"autoboot.txt" => @autoboot, "start4.elf" => "elf", "config.txt" => ""}
        },
        %{size_mb: 32, files: slot_a},
        %{size_mb: 32, files: slot_b}
      ])

    disk
  end
end
