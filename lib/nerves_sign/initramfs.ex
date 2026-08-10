defmodule NervesSign.Initramfs do
  @moduledoc """
  Build the board key helper and assemble the initramfs CPIO.

  Contents are minimal: the cryptinit `init`, the board key helper(s),
  `/etc/initramfs.conf`, and empty mountpoints (cryptinit mounts them itself).
  No libc, no busybox. Then `cpio --format=newc | gzip`.
  """
  require Logger

  @doc """
  Build the key helper with the toolchain, stage the root, and produce
  `initramfs.cpio.gz` in `out_dir`. Returns its path.

  `spec`:
    * `:board` - board atom
    * `:toolchain` - `%{cc, strip}` from `NervesSign.Toolchain`
    * `:init` - path to the built cryptinit init
    * `:initramfs_conf` - path to the initramfs.conf to embed
  """
  @spec assemble(%{
          board: atom(),
          toolchain: %{cc: Path.t(), strip: Path.t()},
          init: Path.t(),
          initramfs_conf: Path.t()
        }) :: Path.t()
  def assemble(%{board: board, toolchain: tc, init: init, initramfs_conf: conf}) do
    unlock = build_helper(board, tc)

    root = Path.join(Briefly.create!(directory: true), "cpio_root")
    for d <- ~w(dev proc sys mnt usr/sbin etc), do: File.mkdir_p!(Path.join(root, d))

    install(init, Path.join(root, "init"))
    install(unlock, Path.join(root, "usr/sbin/unlock"))
    File.cp!(conf, Path.join(root, "etc/initramfs.conf"))

    out = Path.join(Path.dirname(root), "initramfs.cpio.gz")
    pack(root, out)
    Logger.info("nerves_sign: initramfs.cpio.gz = #{File.stat!(out).size} bytes")
    out
  end

  defp build_helper(board, %{cc: cc, strip: strip}) do
    src = NervesSign.Board.key_helper_source(board)
    dir = Path.dirname(src)
    Logger.info("nerves_sign: building key helper (#{src})")

    # The helper Makefile builds `unlock` from unlock.c. If a project points
    # key_helper_source elsewhere, build that file directly.
    helper =
      if Path.basename(src) == "unlock.c" and File.exists?(Path.join(dir, "Makefile")) do
        env = NervesSign.Build.clean_env()
        {_, 0} = System.cmd("make", ["-C", dir, "clean"], stderr_to_stdout: true, env: env)

        args = ["-C", dir, "CC=#{cc}", "CFLAGS=-Wall -Wextra -Os", "LDFLAGS=-static"]
        {_, 0} = System.cmd("make", args, stderr_to_stdout: true, env: env)
        Path.join(dir, "unlock")
      else
        out = Path.join(Briefly.create!(directory: true), "unlock")

        {_, 0} =
          System.cmd(cc, ["-Wall", "-Wextra", "-Os", "-static", "-o", out, src],
            env: NervesSign.Build.clean_env()
          )

        out
      end

    {_, 0} = System.cmd(strip, [helper])
    helper
  end

  defp install(src, dest) do
    File.cp!(src, dest)
    File.chmod!(dest, 0o755)
  end

  defp pack(root, out) do
    main = out <> ".main"
    script = "find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -9 > #{main}"

    case System.cmd("sh", ["-c", script], cd: root, stderr_to_stdout: true) do
      {_, 0} ->
        File.write!(out, :zlib.gzip(device_nodes_cpio()) <> File.read!(main))
        File.rm!(main)
        :ok

      {o, c} ->
        Mix.raise("nerves_sign: cpio assembly failed (#{c}):\n#{o}")
    end
  end

  # The kernel opens /dev/console for /init's stdio, and cryptinit opens
  # /dev/kmsg in log_init(), both before devtmpfs is mounted. Without the
  # device nodes in the archive every cryptinit message is silently lost
  # ("Warning: unable to open an initial console"). mknod needs root, which
  # the build doesn't have, so a tiny newc archive carrying just the nodes is
  # synthesized byte-for-byte and prepended as its own gzip member: the
  # kernel unpacks concatenated compressed archives.
  defp device_nodes_cpio do
    entries = [
      {"dev", 0o040755, 0, 0},
      {"dev/console", 0o020600, 5, 1},
      {"dev/kmsg", 0o020644, 1, 11}
    ]

    body =
      entries
      |> Enum.with_index(1)
      |> Enum.map(fn {{name, mode, rmaj, rmin}, ino} -> newc_entry(name, mode, rmaj, rmin, ino) end)

    IO.iodata_to_binary(body ++ [newc_entry("TRAILER!!!", 0, 0, 0, 0)])
  end

  # newc header: magic then 13 8-digit hex fields: ino mode uid gid nlink
  # mtime filesize devmajor devminor rdevmajor rdevminor namesize check.
  defp newc_entry(name, mode, rmaj, rmin, ino) do
    fields = [ino, mode, 0, 0, 1, 0, 0, 0, 0, rmaj, rmin, byte_size(name) + 1, 0]
    header = "070701" <> Enum.map_join(fields, &hex8/1)
    pad4(header <> name <> <<0>>)
  end

  defp hex8(n), do: n |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(8, "0")

  defp pad4(bin) do
    case rem(byte_size(bin), 4) do
      0 -> bin
      r -> bin <> :binary.copy(<<0>>, 4 - r)
    end
  end
end
