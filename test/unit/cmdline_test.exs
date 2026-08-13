defmodule NervesSign.CmdlineTest do
  @moduledoc """
  The whole cmdline is handed to the kernel verbatim, so the output has to be
  one clean line — a stray comment or newline becomes a bogus kernel parameter.
  """
  use ExUnit.Case, async: true

  alias NervesSign.Cmdline

  @hash "19b5f2b77f9fe7cad032149a1397c980b176fe01e227341d652fd821d48d8efd"

  setup do
    path = Path.join(System.tmp_dir!(), "cmdline_#{System.unique_integer([:positive])}.txt")
    on_exit(fn -> File.rm(path) end)
    {:ok, path: path}
  end

  defp render(path, body, hash \\ @hash) do
    File.write!(path, body)
    Cmdline.with_roothash(path, hash)
  end

  test "appends the root hash", %{path: path} do
    assert render(path, "console=ttyS0 root=/dev/mmcblk0p2\n") ==
             "console=ttyS0 root=/dev/mmcblk0p2 verity_roothash=#{@hash}\n"
  end

  test "output is always exactly one line", %{path: path} do
    out = render(path, "# a comment\nconsole=ttyS0\n\nroot=/dev/mmcblk0p2\n\n")

    assert out == "console=ttyS0 root=/dev/mmcblk0p2 verity_roothash=#{@hash}\n"
    assert out |> String.trim_trailing() |> String.split("\n") |> length() == 1
  end

  test "drops comments and blank lines", %{path: path} do
    out = render(path, "#!/comment\n  # indented comment\nquiet\n   \n")

    refute out =~ "comment"
    assert out == "quiet verity_roothash=#{@hash}\n"
  end

  test "replaces an existing root hash rather than appending a second", %{path: path} do
    out = render(path, "console=ttyS0 verity_roothash=STALE quiet\n")

    refute out =~ "STALE"
    assert out == "console=ttyS0 quiet verity_roothash=#{@hash}\n"
    assert length(Regex.scan(~r/verity_roothash=/, out)) == 1
  end

  test "replaces a stale hash even when it is the only parameter", %{path: path} do
    assert render(path, "verity_roothash=STALE\n") == "verity_roothash=#{@hash}\n"
  end

  test "an empty template still yields the trust anchor", %{path: path} do
    assert render(path, "") == "verity_roothash=#{@hash}\n"
  end

  test "collapses parameters spread over multiple lines", %{path: path} do
    out = render(path, "console=ttyS0,115200\nroot=/dev/mmcblk0p2 ro\nrootwait\n")

    assert out ==
             "console=ttyS0,115200 root=/dev/mmcblk0p2 ro rootwait verity_roothash=#{@hash}\n"
  end

  test "the shipped rpi4 template renders to a bootable-looking line" do
    template = Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4", "cmdline.txt"])
    out = Cmdline.with_roothash(template, @hash)

    assert out =~ "root=/dev/mmcblk0p2"
    assert out =~ "rootfstype=squashfs"
    assert out =~ " ro "
    assert String.ends_with?(out, "verity_roothash=#{@hash}\n")
  end
end
