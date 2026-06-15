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
        {_, 0} = System.cmd("make", ["-C", dir, "clean"], stderr_to_stdout: true)
        {_, 0} = System.cmd("make", ["-C", dir, "CC=#{cc}"], stderr_to_stdout: true)
        Path.join(dir, "unlock")
      else
        out = Path.join(Briefly.create!(directory: true), "unlock")
        {_, 0} = System.cmd(cc, ["-Wall", "-Wextra", "-Os", "-static", "-o", out, src])
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
    script = "find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -9 > #{out}"

    case System.cmd("sh", ["-c", script], cd: root, stderr_to_stdout: true) do
      {_, 0} -> :ok
      {o, c} -> Mix.raise("nerves_sign: cpio assembly failed (#{c}):\n#{o}")
    end
  end
end
