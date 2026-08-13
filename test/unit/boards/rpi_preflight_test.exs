defmodule NervesSign.Boards.RPi.PreflightTest do
  @moduledoc """
  The Raspberry Pi boot firmware contract — family-wide, not one board. The
  VideoCore firmware reads config.txt out of the FAT image before the ARM cores
  start, and a config that never names the initramfs produces an image that
  builds, signs, verifies, and boots straight past dm-verity.

  Exercised through `NervesSign.Boards.RPi4` since that is the board that
  exists, but nothing here is rpi4-specific: the same contract holds for any Pi.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias NervesSign.Boards.RPi4

  @good_config """
  arm_64bit=1
  boot_ramdisk=1
  kernel=Image
  initramfs rootfs.cpio.gz
  cmdline=cmdline.txt
  """

  setup do
    dir = Path.join(System.tmp_dir!(), "rpi4_pre_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    fwup = Path.join(dir, "boot_fwup.conf")
    File.cp!(Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4", "boot_fwup.conf"]), fwup)

    {:ok, dir: dir, fwup: fwup}
  end

  defp check(c, config_body) do
    path = Path.join(c.dir, "config.txt")
    File.write!(path, config_body)
    RPi4.preflight!(%{board: :rpi4, config_txt: path, boot_fwup_conf: c.fwup})
  end

  test "accepts the config the gen task ships", c do
    assert capture_log(fn -> assert check(c, @good_config) == :ok end) == ""
  end

  test "rejects a config.txt with no initramfs directive", c do
    body = String.replace(@good_config, "initramfs rootfs.cpio.gz\n", "")

    err = assert_raise Mix.Error, ~r/has no `initramfs` directive/, fn -> check(c, body) end
    assert err.message =~ "dm-verity is never set up"
  end

  test "rejects an initramfs that fwup does not pack", c do
    body = String.replace(@good_config, "rootfs.cpio.gz", "initrd.img")

    err = assert_raise Mix.Error, ~r/not packed into boot.img/, fn -> check(c, body) end
    assert err.message =~ "initrd.img"
    # The message lists what is actually in the image, so the fix is obvious.
    assert err.message =~ "rootfs.cpio.gz"
  end

  test "rejects a kernel that fwup does not pack", c do
    body = String.replace(@good_config, "kernel=Image", "kernel=zImage")

    assert_raise Mix.Error, ~r/points its kernel at "zImage"/, fn -> check(c, body) end
  end

  test "rejects an omitted kernel= because the firmware default is not packed", c do
    body = String.replace(@good_config, "kernel=Image\n", "")

    assert_raise Mix.Error, ~r/kernel at "kernel8.img"/, fn -> check(c, body) end
  end

  test "accepts an omitted cmdline= since the default name is what fwup packs", c do
    body = String.replace(@good_config, "cmdline=cmdline.txt\n", "")

    assert capture_log(fn -> assert check(c, body) == :ok end) == ""
  end

  test "rejects a cmdline= naming a file that is not packed", c do
    body = String.replace(@good_config, "cmdline=cmdline.txt", "cmdline=boot.txt")

    assert_raise Mix.Error, ~r/points its cmdline at "boot.txt"/, fn -> check(c, body) end
  end

  test "ignores directives that are commented out", c do
    body = String.replace(@good_config, "initramfs", "# initramfs")

    assert_raise Mix.Error, ~r/has no `initramfs` directive/, fn -> check(c, body) end
  end

  test "ignores trailing comments on a directive", c do
    body = String.replace(@good_config, "kernel=Image", "kernel=Image # the 64-bit kernel")

    assert capture_log(fn -> assert check(c, body) == :ok end) == ""
  end

  test "accepts the address form of the initramfs directive", c do
    body = String.replace(@good_config, "rootfs.cpio.gz", "rootfs.cpio.gz followkernel")

    assert capture_log(fn -> assert check(c, body) == :ok end) == ""
  end

  test "warns but proceeds when boot_ramdisk=1 is missing", c do
    body = String.replace(@good_config, "boot_ramdisk=1\n", "")

    log = capture_log(fn -> assert check(c, body) == :ok end)
    assert log =~ "boot_ramdisk=1"
    assert log =~ "unprovisioned"
  end

  describe "dtoverlay" do
    # Under stock Nerves the boot partition carries all of rpi-firmware's
    # overlays/, so dtoverlay=anything works. In a signed image only what the
    # fwup config names exists, and a missing one is silent at runtime.
    defp with_overlays(body, lines), do: body <> Enum.join(lines, "\n") <> "\n"

    test "accepts the overlays the shipped config.txt asks for", c do
      # The generated project must be self-consistent: every dtoverlay in the
      # shipped config.txt has to be in the shipped boot_fwup.conf.
      shipped = Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4", "config.txt"])
      path = Path.join(c.dir, "config.txt")
      File.cp!(shipped, path)

      assert capture_log(fn ->
               assert RPi4.preflight!(%{config_txt: path, boot_fwup_conf: c.fwup}) == :ok
             end) == ""
    end

    test "warns about an overlay that is not in the signed image", c do
      # w1-gpio-pullup is sitting commented out in entryfy's config.txt, and
      # ex_verity's boot_fwup.conf carried it. Ours does not.
      body = with_overlays(@good_config, ["dtoverlay=w1-gpio-pullup,gpiopin=4"])

      log = capture_log(fn -> assert check(c, body) == :ok end)

      assert log =~ "overlays/w1-gpio-pullup.dtbo"
    end

    test "signs anyway: a missing overlay is a board config bug, not a broken ceremony", c do
      # The image boots and verifies. Refusing to sign it would be deciding how
      # the project configures its board, which is not this library's call.
      body = with_overlays(@good_config, ["dtoverlay=pwm"])

      assert capture_log(fn -> assert check(c, body) == :ok end) =~ "still verifies"
    end

    test "the message explains why it cannot be fixed after the fact", c do
      body = with_overlays(@good_config, ["dtoverlay=pwm"])

      log = capture_log(fn -> check(c, body) end)

      assert log =~ "invalidating"
      assert log =~ "not apply"
      # And shows the fwup lines to add, in the project's own file.
      assert log =~ "file-resource pwm.dtbo"
      assert log =~ "fat_write"
    end

    test "lists every missing overlay at once, deduplicated", c do
      body = with_overlays(@good_config, ["dtoverlay=pwm", "dtoverlay=tc358743", "dtoverlay=pwm"])

      log = capture_log(fn -> check(c, body) end)

      # The list itself, not the worked example further down that repeats one.
      [listed, _explanation] = String.split(log, "The image still boots", parts: 2)

      assert listed =~ "overlays/pwm.dtbo"
      assert listed =~ "overlays/tc358743.dtbo"
      assert length(Regex.scan(~r|overlays/pwm\.dtbo|, listed)) == 1
    end

    test "accepts the parameterised form, which entryfy uses for cm4 host mode", c do
      body = with_overlays(@good_config, ["dtoverlay=dwc2,dr_mode=host"])

      assert capture_log(fn -> assert check(c, body) == :ok end) == ""
    end

    test "a bare dtoverlay= only terminates the previous overlay's parameters", c do
      body = with_overlays(@good_config, ["dtoverlay=dwc2", "dtoverlay="])

      assert capture_log(fn -> assert check(c, body) == :ok end) == ""
    end

    test "accepts a name written with its .dtbo suffix", c do
      body = with_overlays(@good_config, ["dtoverlay=dwc2.dtbo"])

      assert capture_log(fn -> assert check(c, body) == :ok end) == ""
    end

    test "a commented-out overlay needs nothing packed", c do
      # entryfy carries these commented out; uncommenting one is exactly the
      # change this check exists to catch.
      body =
        with_overlays(@good_config, ["#dtoverlay=w1-gpio-pullup,gpiopin=4", "# dtoverlay=pwm"])

      assert capture_log(fn -> assert check(c, body) == :ok end) == ""
    end

    test "dtparam never needs an overlay file", c do
      # dtparam applies to the base device tree, not an overlay.
      body =
        with_overlays(@good_config, ["dtparam=i2c_arm=on", "dtparam=spi=on", "dtparam=audio=on"])

      assert capture_log(fn -> assert check(c, body) == :ok end) == ""
    end

    test "an overlay under a board filter is still required", c do
      # Conditional filters are not interpreted, so [cm4] reads as always. For
      # this check that is the safe direction: an unused 2 KB overlay in the
      # image costs nothing, a missing one costs a driver.
      body = with_overlays(@good_config, ["[cm4]", "dtoverlay=tc358743"])

      assert capture_log(fn -> assert check(c, body) == :ok end) =~ "tc358743"
    end
  end

  test "validates against the project's own fwup config, not a hardcoded list", c do
    # A project that renamed resources in its own boot_fwup.conf must validate
    # against its layout, or the check would force everyone onto ours.
    renamed = Path.join(c.dir, "renamed_fwup.conf")

    File.write!(
      renamed,
      c.fwup |> File.read!() |> String.replace(~s|"rootfs.cpio.gz"|, ~s|"initrd.img"|)
    )

    path = Path.join(c.dir, "config.txt")
    File.write!(path, String.replace(@good_config, "rootfs.cpio.gz", "initrd.img"))

    assert capture_log(fn ->
             assert RPi4.preflight!(%{config_txt: path, boot_fwup_conf: renamed}) == :ok
           end) == ""
  end

  test "ignores context keys it has no use for", c do
    # ctx is a map so it can grow for other boards without breaking this one.
    path = Path.join(c.dir, "config.txt")
    File.write!(path, @good_config)

    ctx = %{
      board: :rpi4,
      config_txt: path,
      boot_fwup_conf: c.fwup,
      cmdline: "root=/dev/mmcblk0p2 ro\n",
      app_dir: c.dir,
      something_a_future_board_needs: :ignored
    }

    assert capture_log(fn -> assert RPi4.preflight!(ctx) == :ok end) == ""
  end
end
