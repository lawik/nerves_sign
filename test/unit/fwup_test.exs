defmodule NervesSign.FwupTest do
  use ExUnit.Case, async: true

  alias NervesSign.Fwup

  @shipped Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4", "boot_fwup.conf"])

  test "reads the fat_write targets out of the shipped rpi4 boot config" do
    files = Fwup.fat_files(@shipped)

    assert "Image" in files
    assert "rootfs.cpio.gz" in files
    assert "cmdline.txt" in files
    assert "config.txt" in files
  end

  test "keeps the subdirectory an overlay is written into" do
    files = Fwup.fat_files(@shipped)

    # config.txt's `dtoverlay=NAME` resolves to overlays/NAME.dtbo, so the
    # directory is part of the name.
    assert "overlays/vc4-kms-v3d.dtbo" in files
    assert "overlays/overlay_map.dtb" in files
  end

  test "reflects the rename a resource undergoes on the way in" do
    files = Fwup.fat_files(@shipped)

    # The source is ramoops.dtb; it lands as an overlay.
    assert "overlays/ramoops.dtbo" in files
    refute "ramoops.dtb" in files
  end

  test "ignores file-resource declarations, which are not what lands in the FAT", %{} do
    conf = Path.join(System.tmp_dir!(), "fwup_#{System.unique_integer([:positive])}.conf")

    File.write!(conf, """
    file-resource decoy.bin { host-path = "${SOURCE}/decoy.bin" }

    task complete {
        on-resource decoy.bin { raw_write(${OFFSET}) }
        on-resource real.bin { fat_write(${OFFSET}, "real.bin") }
    }
    """)

    on_exit(fn -> File.rm(conf) end)

    files = Fwup.fat_files(conf)

    # raw_write does not put a file in the filesystem the firmware browses.
    assert files == MapSet.new(["real.bin"])
  end
end
