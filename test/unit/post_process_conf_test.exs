defmodule NervesSign.PostProcessConfTest do
  use ExUnit.Case, async: true

  alias NervesSign.PostProcess

  # Where the cryptinit config comes from decides whether a fleet device can
  # mount its rootfs, so every branch is pinned down: config-declared
  # settings, a configured file path, the conventional file, nothing at all —
  # and the two ambiguous combinations that must refuse.

  @settings [
    rootfs_key: "cmd:/usr/sbin/bootstrap-or-derive --raw /dev/mmcblk0p2 /dev/mmcblk0p4 aes-cbc-plain",
    rootfs_cipher: "aes-cbc-plain"
  ]

  setup do
    app_dir = Path.join(System.tmp_dir!(), "ns_conf_#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(app_dir, "config/rpi4"))
    on_exit(fn -> File.rm_rf(app_dir) end)
    %{app_dir: app_dir, conventional: Path.join(app_dir, "config/rpi4/initramfs.conf")}
  end

  test "nothing configured, no file: verity only", %{app_dir: app_dir} do
    assert PostProcess.resolve_initramfs_conf([], app_dir, :rpi4) == nil
  end

  test "nothing configured, conventional file: the file", ctx do
    File.write!(ctx.conventional, "rootfs_cipher = aes-cbc-plain\n")
    assert PostProcess.resolve_initramfs_conf([], ctx.app_dir, :rpi4) == ctx.conventional
  end

  test "an explicitly configured path wins over the conventional file", ctx do
    File.write!(ctx.conventional, "# decoy\n")
    other = Path.join(ctx.app_dir, "elsewhere.conf")
    File.write!(other, "rootfs_cipher = aes-cbc-plain\n")

    assert PostProcess.resolve_initramfs_conf([initramfs_conf: other], ctx.app_dir, :rpi4) ==
             other
  end

  test "config-declared settings pass through untouched", %{app_dir: app_dir} do
    assert PostProcess.resolve_initramfs_conf([cryptinit: @settings], app_dir, :rpi4) ==
             @settings
  end

  test "declared settings plus a stray conventional file refuse the build", ctx do
    # The exact situation the mechanism exists for: `mix nerves_sign.gen`
    # regenerated the file with fresh-fleet defaults. Silently preferring
    # either side ships firmware somebody did not choose.
    File.write!(ctx.conventional, "rootfs_cipher = aes-xts-plain64\n")

    err =
      assert_raise Mix.Error, fn ->
        PostProcess.resolve_initramfs_conf([cryptinit: @settings], ctx.app_dir, :rpi4)
      end

    assert err.message =~ "authoritative"
    assert err.message =~ ctx.conventional
  end

  test "settings and a configured file path together refuse the build", ctx do
    assert_raise Mix.Error, fn ->
      PostProcess.resolve_initramfs_conf(
        [cryptinit: @settings, initramfs_conf: "somewhere.conf"],
        ctx.app_dir,
        :rpi4
      )
    end
  end
end
