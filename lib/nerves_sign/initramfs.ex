defmodule NervesSign.Initramfs do
  @moduledoc """
  Assemble the initramfs CPIO.

  Contents are minimal: the cryptinit `init`, the board key helper(s),
  `/etc/initramfs.conf`, and empty mountpoints (`/dev /proc /sys /mnt` —
  cryptinit mounts them itself). No libc, no busybox.

      <root>/init                   cryptinit (static)
      <root>/usr/sbin/unlock        board key helper (static)
      <root>/etc/initramfs.conf     cryptinit config
      <root>/{dev,proc,sys,mnt}     empty dirs

  Then `cpio --format=newc | gzip` -> `initramfs.cpio.gz`.
  """

  @doc """
  Stage the given files into a temp root and produce a gzipped newc CPIO.
  Returns the path to `initramfs.cpio.gz`.

  TODO(milestone 3): stage init + helpers + initramfs.conf + dirs, run
  `find . | cpio --null -o --format=newc | gzip`. (cryptinit's
  tests/qemu/assemble.sh is the reference.)
  """
  @spec assemble(%{
          init: Path.t(),
          helpers: [{dest :: String.t(), src :: Path.t()}],
          initramfs_conf: Path.t()
        }) :: Path.t()
  def assemble(_spec) do
    raise "TODO: assemble CPIO (see PLAN.md milestone 3)"
  end
end
