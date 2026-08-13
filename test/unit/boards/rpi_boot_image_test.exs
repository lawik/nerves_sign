defmodule NervesSign.Boards.RPi.BootImageTest do
  @moduledoc """
  The `boot.sig` format is what the Pi bootloader EEPROM reads before it will
  run anything, and it is picky: the first line must be a bare digest, which is
  not what `sha256sum` prints. Until now this was only ever exercised through
  the full pipeline.

  `build/3` needs fwup and a system images dir, so it stays in the integration
  tier; signing needs only openssl.
  """
  use ExUnit.Case, async: true

  alias NervesSign.Boards.RPi.BootImage

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp} do
    key = Path.join(tmp, "boot.pem")
    pub = Path.join(tmp, "boot.pub.pem")

    {_, 0} = System.cmd("openssl", ["genrsa", "-out", key, "2048"], stderr_to_stdout: true)

    {_, 0} =
      System.cmd("openssl", ["rsa", "-in", key, "-pubout", "-out", pub], stderr_to_stdout: true)

    boot_img = Path.join(tmp, "boot.img")
    File.write!(boot_img, :crypto.strong_rand_bytes(64 * 1024))

    {:ok, key: key, pub: pub, boot_img: boot_img}
  end

  defp sig_lines(path), do: path |> File.read!() |> String.split("\n", trim: true)

  test "writes boot.sig alongside boot.img", c do
    assert {:ok, sig} = BootImage.sign(c.boot_img, c.key)

    assert sig == Path.join(Path.dirname(c.boot_img), "boot.sig")
    assert File.exists?(sig)
  end

  test "the first line is a bare digest, not sha256sum's two-column output", c do
    {:ok, sig} = BootImage.sign(c.boot_img, c.key)

    [digest | _] = sig_lines(sig)

    # sha256sum appends "  <filename>", which the bootloader rejects outright.
    assert digest =~ ~r/^[0-9a-f]{64}$/
    refute digest =~ "boot.img"
  end

  test "the digest is actually the digest of the image", c do
    {:ok, sig} = BootImage.sign(c.boot_img, c.key)

    expected =
      :sha256 |> :crypto.hash(File.read!(c.boot_img)) |> Base.encode16(case: :lower)

    assert hd(sig_lines(sig)) == expected
  end

  test "carries a timestamp and an rsa2048 line, in that order", c do
    {:ok, sig} = BootImage.sign(c.boot_img, c.key)

    assert [_digest, ts, rsa] = sig_lines(sig)
    assert ts =~ ~r/^ts: \d+$/
    assert rsa =~ ~r/^rsa2048: [0-9a-f]+$/
  end

  test "the timestamp is a plausible unix time", c do
    {:ok, sig} = BootImage.sign(c.boot_img, c.key)

    [_, "ts: " <> ts, _] = sig_lines(sig)

    # Not a millisecond timestamp, and not a stale constant.
    assert abs(String.to_integer(ts) - System.system_time(:second)) < 300
  end

  test "the signature is hex of exactly one RSA-2048 block", c do
    {:ok, sig} = BootImage.sign(c.boot_img, c.key)

    [_, _, "rsa2048: " <> hex] = sig_lines(sig)

    assert {:ok, raw} = Base.decode16(hex, case: :lower)
    assert byte_size(raw) == 256
  end

  test "openssl verifies the signature against the public key", c do
    {:ok, sig} = BootImage.sign(c.boot_img, c.key)
    [_, _, "rsa2048: " <> hex] = sig_lines(sig)

    raw_sig = Path.join(c.tmp_dir, "sig.bin")
    File.write!(raw_sig, Base.decode16!(hex, case: :lower))

    assert {_, 0} =
             System.cmd(
               "openssl",
               ["dgst", "-sha256", "-verify", c.pub, "-signature", raw_sig, c.boot_img],
               stderr_to_stdout: true
             )
  end

  test "a tampered image fails that verification", c do
    {:ok, sig} = BootImage.sign(c.boot_img, c.key)
    [_, _, "rsa2048: " <> hex] = sig_lines(sig)

    raw_sig = Path.join(c.tmp_dir, "sig.bin")
    File.write!(raw_sig, Base.decode16!(hex, case: :lower))

    <<head::binary-size(16), byte, tail::binary>> = File.read!(c.boot_img)
    File.write!(c.boot_img, <<head::binary, Bitwise.bxor(byte, 0xFF), tail::binary>>)

    assert {_, code} =
             System.cmd(
               "openssl",
               ["dgst", "-sha256", "-verify", c.pub, "-signature", raw_sig, c.boot_img],
               stderr_to_stdout: true
             )

    assert code != 0
  end

  test "an unreadable private key fails loudly rather than writing a bad sig", c do
    err =
      assert_raise Mix.Error, ~r/signing failed/, fn ->
        BootImage.sign(c.boot_img, Path.join(c.tmp_dir, "nope.pem"))
      end

    # openssl explains itself on stderr; without capturing it the raise is an
    # exit code and nothing to act on.
    assert err.message =~ "private key"
    refute File.exists?(Path.join(c.tmp_dir, "boot.sig"))
  end

  describe "copy_outer_txts!/3" do
    test "places the outer pair next to boot.img under their outer_ names", c do
      config = Path.join(c.tmp_dir, "config.txt")
      cmdline = Path.join(c.tmp_dir, "cmdline.txt")
      File.write!(config, "boot_ramdisk=1\n")
      File.write!(cmdline, "root=/dev/mmcblk0p2 ro\n")

      assert BootImage.copy_outer_txts!(c.boot_img, config, cmdline) == :ok

      dir = Path.dirname(c.boot_img)
      assert File.read!(Path.join(dir, "outer_config.txt")) == "boot_ramdisk=1\n"
      assert File.read!(Path.join(dir, "outer_cmdline.txt")) == "root=/dev/mmcblk0p2 ro\n"
    end
  end
end
