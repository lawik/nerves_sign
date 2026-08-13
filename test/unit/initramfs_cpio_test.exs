defmodule NervesSign.InitramfsCpioTest do
  @moduledoc """
  The device-node archive is newc CPIO written by hand, byte by byte. If it is
  malformed the kernel silently drops the whole member and every cryptinit
  message disappears — which looks like a hang, not a parse error. So this
  parses the bytes back with the real `cpio` and checks the node types.
  """
  use ExUnit.Case, async: true

  alias NervesSign.Initramfs

  @cpio System.find_executable("cpio")

  setup do
    dir = Path.join(System.tmp_dir!(), "cpio_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    {:ok, dir: dir}
  end

  test "is a newc archive: magic, 4-byte alignment, trailer" do
    bin = Initramfs.device_nodes_cpio()

    assert <<"070701", _::binary>> = bin
    assert rem(byte_size(bin), 4) == 0
    assert bin =~ "TRAILER!!!"
  end

  test "every header is the full 110 bytes of newc fields" do
    bin = Initramfs.device_nodes_cpio()

    # magic (6) + 13 fields x 8 hex chars = 110, and each field must be hex.
    for [_, fields] <- Regex.scan(~r/070701([0-9a-f]{104})/, bin) do
      assert byte_size(fields) == 104
    end

    assert length(Regex.scan(~r/070701/, bin)) == 4
  end

  if is_nil(@cpio) do
    @tag skip: "cpio not found on this host"
  end

  test "cpio parses it and sees the right device nodes", c do
    archive = Path.join(c.dir, "nodes.cpio")
    File.write!(archive, Initramfs.device_nodes_cpio())

    # Listing rather than extracting: mknod needs root, and CI should not.
    {listing, 0} = System.cmd("sh", ["-c", "#{@cpio} -tv < #{archive}"], stderr_to_stdout: true)

    # The kernel opens /dev/console for init's stdio before devtmpfs exists.
    assert listing =~ ~r/^c.*\s5,\s*1\s.*dev\/console$/m
    # cryptinit's log_init() writes to /dev/kmsg.
    assert listing =~ ~r/^c.*\s1,\s*11\s.*dev\/kmsg$/m
    # And the directory they live in, or the nodes have nowhere to land.
    assert listing =~ ~r/^d.*dev$/m
  end

  test "console is mode 0600 and kmsg 0644, owned by root" do
    bin = Initramfs.device_nodes_cpio()

    assert %{"dev" => dev, "dev/console" => console, "dev/kmsg" => kmsg} = parse(bin)

    assert console.mode == 0o020600
    assert kmsg.mode == 0o020644
    assert dev.mode == 0o040755

    # Wrong major/minor here means cryptinit logs into the wrong device.
    assert console.dev == {5, 1}
    assert kmsg.dev == {1, 11}

    for e <- [dev, console, kmsg] do
      assert e.uid == 0
      assert e.gid == 0
      assert e.filesize == 0
    end
  end

  test "inodes are distinct so the kernel does not treat entries as hardlinks" do
    inodes = parse(Initramfs.device_nodes_cpio()) |> Map.values() |> Enum.map(& &1.ino)

    assert length(Enum.uniq(inodes)) == length(inodes)
  end

  test "gzips to a member the kernel can concatenate ahead of the main archive" do
    gz = :zlib.gzip(Initramfs.device_nodes_cpio())

    assert <<0x1F, 0x8B, _::binary>> = gz
    assert :zlib.gunzip(gz) == Initramfs.device_nodes_cpio()
  end

  # A minimal newc reader, so the assertions above are about the bytes rather
  # than about the writer's own arithmetic.
  defp parse(bin), do: parse(bin, %{})

  defp parse(<<"070701", header::binary-size(104), rest::binary>>, acc) do
    fields = for <<f::binary-size(8) <- header>>, do: String.to_integer(f, 16)
    [ino, mode, uid, gid, _nlink, _mtime, filesize | tail] = fields
    [_devmaj, _devmin, rmaj, rmin, namesize, _check] = tail

    <<name::binary-size(namesize), rest::binary>> = rest
    name = String.trim_trailing(name, <<0>>)
    # The name is padded so the entry ends on a 4-byte boundary.
    padding = rem(4 - rem(110 + namesize, 4), 4)
    <<_::binary-size(padding), rest::binary>> = rest

    if name == "TRAILER!!!" do
      acc
    else
      entry = %{ino: ino, mode: mode, uid: uid, gid: gid, filesize: filesize, dev: {rmaj, rmin}}
      parse(rest, Map.put(acc, name, entry))
    end
  end
end
