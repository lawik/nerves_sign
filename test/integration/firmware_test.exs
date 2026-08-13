defmodule NervesSign.Integration.FirmwareTest do
  @moduledoc """
  Drives the **outer** `fwup.conf` — the one the gen task scaffolds and the
  firmware project owns — for real, and boots what comes out.

  `secure_boot_test.exs` hand-builds its disk, so it proves the signing
  ceremony but says nothing about the layout we ship. This runs the actual
  file: `fwup -c` to build a .fw, `fwup -a -t complete` to write a disk, then
  BodgeRPiBootTest as the bootloader.

  The scheme under test is the one nerves_sign currently ships: MBR-swap A/B,
  no autoboot.txt, lifted from the pre-tryboot Nerves rpi4 layout. Because the
  MBR is rewritten on upgrade, the active rootfs is always the same Linux
  device, which is why one signed cmdline serves both slots.
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

  # From the shipped fwup_include/fwup-common.conf. Asserted against rather
  # than derived, so a change to the layout has to be deliberate.
  @boot_a_offset 63
  @boot_a_count 38630
  @boot_b_offset 38693
  @rootfs_a_offset 77324

  setup_all do
    root = Path.join(System.tmp_dir!(), "ns_fw_#{System.unique_integer([:positive])}")
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

    fw = build_fw!(root, sys, app)
    disk = apply_task!(root, fw, "complete", "disk.img")

    {:ok, root: root, sys: sys, app: app, fw: fw, disk: disk, key: key, pub: pub}
  end

  test "the shipped fwup.conf builds a firmware archive", c do
    assert File.exists?(c.fw)

    # fwup validates the whole config on create, so this failing means the file
    # we scaffold into every project is broken.
    {tasks, 0} = System.cmd("fwup", ["-l", "-i", c.fw], stderr_to_stdout: true)
    tasks = String.split(tasks, "\n", trim: true)

    assert "complete" in tasks
    assert "upgrade.a" in tasks
    assert "upgrade.b" in tasks
    assert "provision" in tasks
  end

  test "it lays down the partition table the layout documents", c do
    parts = partitions(c.disk)

    # Three entries only: active boot, active rootfs, app. The inactive slots
    # exist on disk but are deliberately not in the MBR — that is what makes
    # the MBR-swap scheme work.
    assert length(parts) == 3

    assert [boot, rootfs, app] = parts
    assert boot.start == @boot_a_offset
    assert boot.size == @boot_a_count
    assert boot.type == 0x0C
    assert rootfs.start == @rootfs_a_offset
    assert rootfs.type == 0x83
    assert app.type == 0x83
  end

  test "the boot partition carries only the signed image and the outer txts", c do
    files = fat_files(c.disk, @boot_a_offset)

    assert Enum.sort(files) == ~w(boot.img boot.sig cmdline.txt config.txt)
  end

  test "the rootfs written to disk is the verity-formatted one", c do
    # squashfs magic at the partition start, and the hash tree past the image.
    <<magic::binary-size(4), _::binary>> = read_at(c.disk, @rootfs_a_offset, 4)
    assert magic == "hsqs"
  end

  test "the signed image on disk still verifies after fwup wrote it", c do
    boot_img = extract(c, @boot_a_offset, "boot.img")
    boot_sig = extract(c, @boot_a_offset, "boot.sig")

    assert BodgeRPiBootTest.verify(boot_img, boot_sig, c.pub) == :ok
  end

  describe "booting the real disk" do
    @describetag :known_gap

    test "the bootloader model refuses this layout, and that is bodge's limit not ours", c do
      # BodgeRPiBootTest treats "FAT partition containing start4.elf/start.elf"
      # as what makes a partition bootable. Our boot partition carries only
      # boot.img, boot.sig and the two outer txts, so it refuses.
      #
      # We are not adding one. The GPU firmware this board runs is start4x.elf,
      # pinned by start_file= in config.txt and packed inside boot.img, where it
      # is covered by boot.sig. A second copy loose on the boot partition would
      # be a different variant, unsigned, and never loaded on the signed path —
      # which is the opposite of what secure boot is for. It would not fit
      # either: 1,952,768 bytes free against 2,262,304 for start4.elf.
      #
      # So bodge's heuristic models the unsigned boot flow, where the bootloader
      # scans partitions for firmware. Under boot_ramdisk=1 with signed boot the
      # firmware comes out of the verified image instead. Recorded here so the
      # refusal is understood rather than rediscovered.
      disk = copy_disk!(c, "provisioned")
      :ok = BodgeRPiBootTest.provision(disk, c.pub)

      r = BodgeRPiBootTest.boot(disk)

      refute r.success
      assert r.reason == :no_bootable_partition
    end

    test "the GPU firmware is inside the signature, not loose on the partition", c do
      # The point of the above: start4x.elf is covered by boot.sig. If it moved
      # out to the boot partition it would be swappable without breaking the
      # signature.
      boot_img = extract(c, @boot_a_offset, "boot.img")

      {listing, 0} =
        System.cmd("mdir", ["-b", "-i", boot_img, "::"], stderr_to_stdout: true)

      files = listing |> String.split("\n", trim: true) |> Enum.map(&String.trim/1)

      assert "::/start4x.elf" in files
      assert "::/fixup4x.dat" in files

      # And the boot partition has no firmware of its own to be preferred.
      partition_files = fat_files(c.disk, @boot_a_offset)
      refute Enum.any?(partition_files, &String.starts_with?(&1, "start"))
      refute Enum.any?(partition_files, &String.starts_with?(&1, "fixup"))
    end

    test "the free space in the boot partition is what the numbers above say", c do
      # If someone grows boot.img or the partition, the reasoning in the test
      # above stops being true and should be revisited.
      {out, 0} =
        System.cmd("mdir", ["-i", "#{c.disk}@@#{@boot_a_offset * 512}", "::"],
          stderr_to_stdout: true
        )

      [_, free] = Regex.run(~r/([\d ]+) bytes free/, out)
      free = free |> String.replace(" ", "") |> String.to_integer()

      assert free < 2_262_304,
             "the boot partition now has room for start4.elf; revisit the known gap above"
    end
  end

  describe "the A/B upgrade path" do
    test "upgrade.b writes the B slot and swaps the MBR to it", c do
      disk = copy_disk!(c, "upgrade")
      {out, code} = fwup_apply(disk, c.fw, "upgrade.b")
      assert code == 0, out

      parts = partitions(disk)

      # The MBR now points at the B slot, at the same three entries. This is
      # why root= never changes between slots.
      assert [boot, _rootfs, _app] = parts
      assert boot.start == @boot_b_offset

      assert Enum.sort(fat_files(disk, @boot_b_offset)) ==
               ~w(boot.img boot.sig cmdline.txt config.txt)
    end

    test "the image in the B slot verifies against the same key", c do
      disk = copy_disk!(c, "upgrade_verify")
      {_, 0} = fwup_apply(disk, c.fw, "upgrade.b")

      img = Path.join(c.root, "b_boot.img")
      sig = Path.join(c.root, "b_boot.sig")
      at = "#{disk}@@#{@boot_b_offset * 512}"
      {_, 0} = System.cmd("mcopy", ["-n", "-i", at, "::boot.img", img], stderr_to_stdout: true)
      {_, 0} = System.cmd("mcopy", ["-n", "-i", at, "::boot.sig", sig], stderr_to_stdout: true)

      assert BodgeRPiBootTest.verify(img, sig, c.pub) == :ok
    end

    test "upgrading the slot that is already active is refused", c do
      # upgrade.a guards on the B rootfs being current; a fresh disk is on A.
      disk = copy_disk!(c, "wrong_slot")
      {_out, code} = fwup_apply(disk, c.fw, "upgrade.a")

      assert code != 0
    end
  end

  # -- building ---------------------------------------------------------------

  defp build_fw!(root, sys, app) do
    fw = Path.join(root, "firmware.fw")
    conf = Path.join(app, "config/rpi4/fwup.conf")

    env = %{
      "NERVES_SYSTEM" => sys,
      "NERVES_APP" => app,
      "NERVES_SDK_VERSION" => "0.0.0-test",
      "NERVES_FW_VCS_IDENTIFIER" => "",
      "NERVES_FW_MISC" => ""
    }

    {out, code} =
      System.cmd("fwup", ["-c", "-f", conf, "-o", fw], env: env, stderr_to_stdout: true)

    assert code == 0, "fwup -c failed on the shipped fwup.conf:\n#{out}"
    fw
  end

  defp apply_task!(root, fw, task, name) do
    disk = Path.join(root, name)
    {out, code} = fwup_apply(disk, fw, task)
    assert code == 0, "fwup -a -t #{task} failed:\n#{out}"
    disk
  end

  defp fwup_apply(disk, fw, task) do
    System.cmd("fwup", ["-a", "-i", fw, "-t", task, "-d", disk, "-q", "-y"],
      stderr_to_stdout: true
    )
  end

  defp copy_disk!(c, name) do
    dest = Path.join(c.root, "#{name}.img")
    File.cp!(c.disk, dest)
    dest
  end

  # -- disk inspection --------------------------------------------------------

  defp partitions(disk) do
    <<_::binary-size(446), table::binary-size(64), _::binary>> = read_at(disk, 0, 512)

    for <<entry::binary-size(16) <- table>>, entry != <<0::128>> do
      <<_boot, _chs::binary-size(3), type, _chs2::binary-size(3), start::little-32,
        size::little-32>> = entry

      %{type: type, start: start, size: size}
    end
    |> Enum.reject(&(&1.type == 0))
  end

  defp fat_files(disk, offset) do
    {out, 0} =
      System.cmd("mdir", ["-b", "-i", "#{disk}@@#{offset * 512}", "::"], stderr_to_stdout: true)

    out
    |> String.split("\n", trim: true)
    |> Enum.map(&(&1 |> String.trim() |> String.trim_leading("::/")))
  end

  defp extract(c, offset, name) do
    out = Path.join(c.root, "extracted_#{offset}_#{name}")

    {_, 0} =
      System.cmd("mcopy", ["-n", "-i", "#{c.disk}@@#{offset * 512}", "::#{name}", out],
        stderr_to_stdout: true
      )

    out
  end

  defp read_at(path, block, bytes) do
    {:ok, fd} = :file.open(path, [:read, :binary, :raw])
    {:ok, data} = :file.pread(fd, block * 512, bytes)
    :file.close(fd)
    data
  end

  # -- fixtures ---------------------------------------------------------------

  defp fixture_system!(root) do
    sys = Path.join(root, "system")
    images = Path.join(sys, "images")
    File.mkdir_p!(Path.join(images, "rpi-firmware/overlays"))
    File.mkdir_p!(Path.join(images, "fwup_include"))

    # fwup-common.conf includes this from the system, as real Nerves does.
    File.write!(Path.join(images, "fwup_include/provisioning.conf"), "\n")

    for f <- @dtbs, do: File.write!(Path.join(images, f), filler(f, 4_096))
    File.write!(Path.join(images, "Image"), filler("Image", 1_000_000))
    File.write!(Path.join(images, "rpi-firmware/fixup4x.dat"), filler("fixup4x", 2_048))
    File.write!(Path.join(images, "rpi-firmware/start4x.elf"), filler("start4x", 100_000))

    for f <- @overlays,
        do: File.write!(Path.join(images, "rpi-firmware/overlays/#{f}"), filler(f, 1_024))

    sys
  end

  defp fixture_app!(root) do
    app = Path.join(root, "app")
    conf = Path.join(app, "config/rpi4")
    File.mkdir_p!(Path.join(conf, "fwup_include"))

    # Exactly what `mix nerves_sign.gen.rpi4` scaffolds. The project owns these;
    # the point of this suite is that what we scaffold actually works.
    priv = Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4"])

    for name <-
          ~w(fwup.conf fwup_include/fwup-common.conf boot_fwup.conf config.txt cmdline.txt initramfs.conf) do
      File.cp!(Path.join(priv, name), Path.join(conf, name))
    end

    app
  end

  defp fixture_rootfs!(root) do
    src = Path.join(root, "rootfs_src")
    File.mkdir_p!(src)
    File.write!(Path.join(src, "hello.txt"), "firmware fixture\n")
    out = Path.join(root, "rootfs.squashfs")

    {_, 0} =
      System.cmd("mksquashfs", [src, out, "-quiet", "-no-progress"], stderr_to_stdout: true)

    # The outer fwup.conf reads ${ROOTFS} from the system images dir.
    File.cp!(out, Path.join([root, "system", "images", "rootfs.squashfs"]))
    Path.join([root, "system", "images", "rootfs.squashfs"])
  end

  defp filler(seed, size) do
    :sha256 |> :crypto.hash(seed) |> :binary.copy(div(size, 32) + 1) |> binary_part(0, size)
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

    Application.put_env(:nerves_sign, :rpi_secure_boot, private_key_path: key)
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
end
