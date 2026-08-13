defmodule NervesSign.Integration.QemuBootTest do
  @moduledoc """
  End-to-end runtime boot test on QEMU's `raspi4b` machine.

  This is the full chain, end to end. BodgeRPiBootTest boots a real A/B disk:
  it reads `autoboot.txt`, picks a partition, verifies `boot.sig` against the
  simulated OTP key and extracts the kernel, initramfs and cmdline out of the
  *signed* `boot.img`. Those artifacts — the ones the bootloader actually
  chose, not ones the test picked — are then handed to QEMU, which is where the
  real VPU firmware would hand off to the ARM cores.

  Success means the real kernel started cryptinit, cryptinit opened dm-verity
  with the root hash from the signed cmdline, mounted the squashfs through it,
  switch_rooted and exec'd our marker `/sbin/init`. A wrong partition choice, a
  bad signature or a missing initramfs shows up here as a failed Linux boot.

  Needs a real Nerves system's images dir (kernel with the dm bits =y):

      NERVES_SIGN_TEST_SYSTEM=/path/to/system/with/images \\
        mix test --include integration test/integration/qemu_boot_test.exs
  """
  use ExUnit.Case, async: false

  alias BodgeRPiBootTest.Qemu

  @moduletag :integration
  @moduletag timeout: 600_000

  @marker "NERVES_SIGN_BOOT_OK"

  @real_system System.get_env("NERVES_SIGN_TEST_SYSTEM")

  tools = ~w(veritysetup mksquashfs fwup mcopy cpio gzip make sfdisk qemu-system-aarch64)
  missing = Enum.reject(tools, &System.find_executable/1)

  cond do
    missing != [] ->
      @moduletag skip: "missing host tools: #{Enum.join(missing, ", ")}"

    is_nil(@real_system) ->
      @moduletag skip: "set NERVES_SIGN_TEST_SYSTEM to a built system dir with images/"

    not File.exists?(Path.join(@real_system, "images/Image")) ->
      @moduletag skip: "no images/Image under NERVES_SIGN_TEST_SYSTEM"

    not File.dir?(Path.join(Mix.Project.deps_path(), "nerves_cryptinit/src")) ->
      @moduletag skip: "nerves_cryptinit dep not fetched (run mix deps.get)"

    not BodgeRPiBootTest.Qemu.available?() ->
      @moduletag skip: "qemu-system-aarch64 has no raspi4b machine (needs QEMU 9.0+)"

    true ->
      :ok
  end

  # Files the rpi4 boot_fwup.conf needs from the system images dir.
  @system_files ~w(Image bcm2711-rpi-4-b.dtb bcm2711-rpi-400.dtb bcm2711-rpi-cm4.dtb ramoops.dtb
                   rpi-firmware/fixup4x.dat rpi-firmware/start4x.elf
                   rpi-firmware/overlays/overlay_map.dtb rpi-firmware/overlays/vc4-kms-v3d.dtbo
                   rpi-firmware/overlays/vc4-kms-v3d-pi4.dtbo rpi-firmware/overlays/dwc2.dtbo)

  setup_all do
    root = Path.join(System.tmp_dir!(), "ns_qemu_#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    sys = copy_system!(root)
    app = fixture_app!(root)
    rootfs = fixture_rootfs!(root)

    key = Path.join(root, "key.pem")
    pub = Path.join(root, "key.pub.pem")
    :ok = BodgeRPiBootTest.generate_keys(key, pub)

    configure_nerves_sign!(sys, app, key)

    :ok = NervesSign.PostProcess.run(rootfs)

    images = Path.join(sys, "images")
    disk = build_ab_disk!(root, images, rootfs)

    # Burn the customer key into the simulated OTP and turn on signed boot, so
    # the bootloader actually enforces boot.sig rather than waving it through.
    :ok = BodgeRPiBootTest.provision(disk, pub)

    {:ok, root: root, disk: disk, dtb: Path.join(images, "bcm2711-rpi-4-b.dtb")}
  end

  test "the partition bodge selected boots to userspace on qemu raspi4b", c do
    # 1. The bootloader half: partition selection and signature verification.
    report = BodgeRPiBootTest.boot(c.disk)

    assert report.success, """
    bodge refused to boot the disk:
      reason: #{inspect(report.reason)}
      trace:
        #{Enum.join(report.trace, "\n    ")}
    """

    assert report.chosen.partition == 2, "expected autoboot.txt to select slot A"
    assert report.chosen.signed == 1, "expected signed boot to be enforced"

    # It handed over everything the ARM side needs, out of the signed image.
    assert report.kernel_path

    assert report.initramfs_path,
           "cryptinit lives in the initramfs; nothing to hand off without it"

    assert report.chosen.cmdline =~ ~r/verity_roothash=[0-9a-f]{64}/

    # 2. The QEMU half: continue from exactly those artifacts.
    result = Qemu.run(report, c.disk, await: @marker, timeout: 300_000)

    output =
      case result do
        {:ok, output} -> output
        {:timeout, output} -> output
        {:error, reason} -> flunk("qemu handoff failed: #{inspect(reason)}")
      end

    File.write!(Path.join(c.root, "qemu.log"), output)

    assert output =~ @marker, """
    marker not found; last lines of console:

    #{output |> String.split("\n") |> Enum.take(-160) |> Enum.join("\n")}
    """

    # cryptinit announced itself and nothing in the chain died fatally
    # before the marker.
    assert output =~ "cryptinit"
    [before_marker, _] = String.split(output, @marker, parts: 2)
    refute before_marker =~ "fatal"
  end

  # -- fixtures ---------------------------------------------------------------

  defp copy_system!(root) do
    sys = Path.join(root, "system")
    images = Path.join(sys, "images")

    for f <- @system_files do
      src = Path.join([@real_system, "images", f])
      dst = Path.join(images, f)
      File.mkdir_p!(Path.dirname(dst))
      File.cp!(src, dst)
    end

    sys
  end

  defp fixture_app!(root) do
    app = Path.join(root, "app")
    conf = Path.join(app, "config/rpi4")
    File.mkdir_p!(conf)

    # console=ttyS0: this kernel only has the 8250 miniuart driver (no PL011),
    # matching real Nerves rpi4 serial. "serial0" is an alias only the real
    # firmware rewrites, so the tty is named directly. earlycon catches
    # crashes before the console driver starts. root=mmcblk1p2 because QEMU's
    # raspi4b exposes the SD on the mmc1 controller (real hardware: mmcblk0);
    # p4 because p1..p3 are the AUTOBOOT and A/B boot partitions.
    # Signed as-is, boots as-is.
    File.write!(
      Path.join(conf, "cmdline.txt"),
      "earlycon=uart8250,mmio32,0xfe215040 console=ttyS0,115200 " <>
        "root=/dev/mmcblk1p4 rootfstype=squashfs ro rootwait\n"
    )

    File.write!(Path.join(conf, "config.txt"), """
    arm_64bit=1
    boot_ramdisk=1
    kernel=Image
    initramfs rootfs.cpio.gz
    cmdline=cmdline.txt
    """)

    app
  end

  # A squashfs whose /sbin/init is a static musl binary that prints the
  # marker and reboots (with -no-reboot, that ends QEMU).
  defp fixture_rootfs!(root) do
    src = Path.join(root, "rootfs_src")
    File.mkdir_p!(Path.join(src, "sbin"))
    File.mkdir_p!(Path.join(src, "dev"))
    File.mkdir_p!(Path.join(src, "proc"))
    File.mkdir_p!(Path.join(src, "sys"))

    marker_c = Path.join(root, "marker_init.c")

    # PID1 may have no stdio (the kernel can fail to open the initial
    # console), and /dev in the new root is empty after switch_root, so the
    # marker mounts devtmpfs itself and writes to kmsg/console directly.
    File.write!(marker_c, """
    #include <fcntl.h>
    #include <string.h>
    #include <sys/mount.h>
    #include <sys/reboot.h>
    #include <unistd.h>

    static void emit(const char *path, const char *msg)
    {
        int fd = open(path, O_WRONLY);
        if (fd >= 0) {
            (void) !write(fd, msg, strlen(msg));
            close(fd);
        }
    }

    int main(void)
    {
        const char *msg = "#{@marker}\\n";
        mount("devtmpfs", "/dev", "devtmpfs", 0, "mode=755");
        emit("/dev/kmsg", msg);
        emit("/dev/console", msg);
        (void) !write(STDOUT_FILENO, msg, strlen(msg));
        sync();
        reboot(RB_AUTOBOOT);
        for (;;)
            pause();
    }
    """)

    tc_bin = System.fetch_env!("NERVES_SIGN_TEST_TOOLCHAIN_BIN")
    cc = Path.join(tc_bin, "aarch64-nerves-linux-musl-gcc")

    {_, 0} =
      System.cmd(cc, ["-static", "-Os", "-o", Path.join(src, "sbin/init"), marker_c],
        stderr_to_stdout: true
      )

    out = Path.join(root, "rootfs.squashfs")

    {_, 0} =
      System.cmd("mksquashfs", [src, out, "-quiet", "-no-progress"], stderr_to_stdout: true)

    out
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

  # The same A/B layout secure_boot_test.exs builds — outer txts and a
  # start4.elf stub in each slot, 8 MB autoboot + 32 MB slots — plus the verity
  # rootfs the signed cmdline points at. Padded to a power of two because QEMU
  # rejects odd-sized SD cards.
  defp build_ab_disk!(root, images, rootfs) do
    disk = Path.join(root, "disk.img")

    autoboot = """
    [all]
    tryboot_a_b=1
    boot_partition=2
    [tryboot]
    boot_partition=3
    """

    slot = %{
      "start4.elf" => "elf",
      "boot.img" => File.read!(Path.join(images, "boot.img")),
      "boot.sig" => File.read!(Path.join(images, "boot.sig")),
      "config.txt" => File.read!(Path.join(images, "outer_config.txt")),
      "cmdline.txt" => File.read!(Path.join(images, "outer_cmdline.txt"))
    }

    :ok =
      BodgeRPiBootTest.build_disk(disk, [
        %{
          size_mb: 8,
          files: %{"autoboot.txt" => autoboot, "start4.elf" => "elf", "config.txt" => ""}
        },
        %{size_mb: 32, files: slot},
        %{size_mb: 32, files: slot},
        # 46 MB: the rootfs size this test already used before the A/B layout.
        %{size_mb: 46, type: 0x83, raw: rootfs}
      ])

    {_, 0} = System.cmd("truncate", ["-s", "128M", disk])

    disk
  end
end
