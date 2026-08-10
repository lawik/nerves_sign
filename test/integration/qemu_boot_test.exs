defmodule NervesSign.Integration.QemuBootTest do
  @moduledoc """
  End-to-end runtime boot test on QEMU's `raspi4b` machine.

  Where `secure_boot_test.exs` validates the bootloader contract with
  BootDouble (which stops where the VPU firmware hands off to the ARM cores),
  this tier boots the ARM side for real: the kernel, initramfs and cmdline are
  extracted from the *signed* `boot.img` the pipeline produced, and the disk
  carries the verity-formatted rootfs. Success means the real kernel started
  cryptinit, cryptinit opened dm-verity with the root hash from the signed
  cmdline, mounted the squashfs through it, switch_rooted and exec'd our
  marker `/sbin/init`.

  Needs a real Nerves system's images dir (kernel with the dm bits =y):

      NERVES_SIGN_TEST_SYSTEM=/path/to/system/with/images \\
        mix test --include integration test/integration/qemu_boot_test.exs
  """
  use ExUnit.Case, async: false

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
    :ok = BootDouble.generate_keys(key, pub)

    configure_nerves_sign!(sys, app, key)

    :ok = NervesSign.PostProcess.run(rootfs)

    images = Path.join(sys, "images")
    boot_img = Path.join(images, "boot.img")

    # The pieces that boot are the ones inside the signed image.
    extracted = Path.join(root, "extracted")
    File.mkdir_p!(extracted)

    for f <- ~w(Image rootfs.cpio.gz cmdline.txt) do
      {_, 0} = System.cmd("mcopy", ["-n", "-i", boot_img, "::#{f}", Path.join(extracted, f)])
    end

    sd = build_sd!(root, rootfs)

    {:ok,
     root: root,
     dtb: Path.join(images, "bcm2711-rpi-4-b.dtb"),
     kernel: Path.join(extracted, "Image"),
     initrd: Path.join(extracted, "rootfs.cpio.gz"),
     cmdline: extracted |> Path.join("cmdline.txt") |> File.read!() |> String.trim(),
     sd: sd}
  end

  test "signed boot.img contents boot to userspace on qemu raspi4b", c do
    assert c.cmdline =~ ~r/verity_roothash=[0-9a-f]{64}/

    log = Path.join(c.root, "qemu.log")

    {_, status} =
      System.cmd(
        "timeout",
        [
          "300",
          "qemu-system-aarch64",
          "-M",
          "raspi4b",
          "-kernel",
          c.kernel,
          "-dtb",
          c.dtb,
          "-initrd",
          c.initrd,
          "-append",
          c.cmdline,
          "-drive",
          "file=#{c.sd},if=sd,format=raw",
          "-display",
          "none",
          # The miniuart (ttyS0) is the SECOND serial on QEMU's raspi machines.
          "-serial",
          "null",
          "-serial",
          "stdio",
          "-no-reboot",
          "-monitor",
          "none"
        ],
        into: File.stream!(log),
        stderr_to_stdout: true
      )

    output = File.read!(log)

    assert output =~ @marker, """
    marker not found (qemu exit #{status}); last lines of console:

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
    # raspi4b exposes the SD on the mmc1 controller (real hardware: mmcblk0).
    # Signed as-is, boots as-is.
    File.write!(
      Path.join(conf, "cmdline.txt"),
      "earlycon=uart8250,mmio32,0xfe215040 console=ttyS0,115200 " <>
        "root=/dev/mmcblk1p2 rootfstype=squashfs ro rootwait\n"
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

    Application.put_env(:nerves_sign, :rpi4_secure_boot,
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

  # 64 MiB SD (QEMU wants power-of-two): p1 dummy FAT, p2 the verity rootfs
  # (squashfs + appended hash tree) at the offset cmdline's root= expects.
  defp build_sd!(root, rootfs) do
    sd = Path.join(root, "sd.img")
    {_, 0} = System.cmd("truncate", ["-s", "64M", sd])

    script = """
    label: dos
    unit: sectors

    p1 : start=2048, size=32768, type=c
    p2 : start=34816, size=94208, type=83
    """

    {_, 0} = System.shell("echo '#{script}' | sfdisk --no-reread #{sd}", stderr_to_stdout: true)

    rootfs_size = File.stat!(rootfs).size
    true = rootfs_size <= 94_208 * 512

    {_, 0} =
      System.cmd("dd", [
        "if=#{rootfs}",
        "of=#{sd}",
        "bs=512",
        "seek=34816",
        "conv=notrunc",
        "status=none"
      ])

    sd
  end
end
