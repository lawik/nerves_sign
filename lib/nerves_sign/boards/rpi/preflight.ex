defmodule NervesSign.Boards.RPi.Preflight do
  @moduledoc """
  The Raspberry Pi boot firmware contract: what `config.txt` has to say for the
  firmware to load the kernel and the cryptinit initramfs out of `boot.img`.

  This is the **whole Pi family**, not one board. Every Pi boots the same way —
  the VideoCore firmware reads `config.txt` off the FAT boot filesystem and
  acts on it before the ARM cores start — so the directives, their defaults and
  their failure modes are identical from a Pi 3 to a CM5. What differs per
  board is the *content*: which kernel, which dtbs, which firmware blobs. None
  of that is here.

  Nothing in this module is portable beyond the Pi. An i.MX HAB or TrustZone
  chain has no `config.txt`, no VideoCore, and no FAT boot filesystem to read
  one from; it would implement `c:NervesSign.Board.preflight!/1` from scratch.

  Filenames are read out of the board's fwup config rather than hardcoded, so a
  project that renamed resources in its own `boot_fwup.conf` validates against
  its own layout.

  Known limitation: RPi conditional filters (`[cm4]`, `[all]`, ...) are not
  interpreted. Directives are matched anywhere in the file, so a setting that
  only applies under a filter reads here as globally present.
  """
  require Logger

  alias NervesSign.Fwup

  # The firmware's own defaults when config.txt does not say. On any 64-bit Pi
  # (arm_64bit=1) the default kernel name is kernel8.img.
  @default_kernel "kernel8.img"
  @default_cmdline "cmdline.txt"

  @doc """
  Check `ctx.config_txt` against the files `ctx.boot_fwup_conf` packs into
  boot.img. Raises on anything that would not boot.
  """
  @spec check!(map()) :: :ok
  def check!(%{config_txt: config_txt, boot_fwup_conf: fwup_conf}) do
    packed = Fwup.fat_files(fwup_conf)
    directives = parse(File.read!(config_txt))

    check_initramfs!(directives, packed, config_txt, fwup_conf)
    check_referenced_file!(directives[:kernel] || @default_kernel, "kernel", packed, config_txt)

    check_referenced_file!(
      directives[:cmdline] || @default_cmdline,
      "cmdline",
      packed,
      config_txt
    )

    check_boot_ramdisk(directives, config_txt)
    :ok
  end

  @doc """
  Extract the directives we care about from a `config.txt` body:
  `%{kernel: name, initramfs: name, cmdline: name, boot_ramdisk: "1"}`. Absent
  keys are absent from the map.
  """
  @spec parse(String.t()) :: %{atom() => String.t()}
  def parse(body) do
    body
    |> String.split("\n")
    |> Enum.map(&(&1 |> String.split("#", parts: 2) |> hd() |> String.trim()))
    |> Enum.reduce(%{}, &collect_directive/2)
  end

  defp collect_directive(line, acc) do
    case line do
      # `initramfs <file> [<address>|followkernel]` — space-separated, not `=`.
      "initramfs " <> rest ->
        case String.split(rest) do
          [file | _] -> Map.put(acc, :initramfs, file)
          [] -> acc
        end

      _ ->
        case String.split(line, "=", parts: 2) do
          [k, v] when k in ~w(kernel cmdline boot_ramdisk) ->
            Map.put(acc, String.to_existing_atom(k), String.trim(v))

          _ ->
            acc
        end
    end
  end

  defp check_initramfs!(directives, packed, config_txt, fwup_conf) do
    case directives[:initramfs] do
      nil ->
        Mix.raise("""
        nerves_sign: #{config_txt} has no `initramfs` directive.

        Without it the firmware boots the kernel directly and cryptinit never
        runs, so dm-verity is never set up and the signed verity_roothash= is
        ignored. The image would still build and sign — it just would not be
        verified. Add the initramfs the boot fwup config packs, e.g.

            initramfs rootfs.cpio.gz
        """)

      name ->
        check_referenced_file!(name, "initramfs", packed, config_txt, fwup_conf)
    end
  end

  defp check_referenced_file!(name, kind, packed, config_txt, fwup_conf \\ nil) do
    unless MapSet.member?(packed, name) do
      Mix.raise("""
      nerves_sign: #{config_txt} points its #{kind} at "#{name}", which is not \
      packed into boot.img#{if fwup_conf, do: " by #{fwup_conf}", else: ""}.

      The firmware would not find it at boot. Files written into the image:
        #{packed |> Enum.sort() |> Enum.join("\n  ")}
      """)
    end
  end

  defp check_boot_ramdisk(directives, config_txt) do
    unless directives[:boot_ramdisk] == "1" do
      Logger.warning("""
      nerves_sign: #{config_txt} does not set `boot_ramdisk=1`.

      This same file ships as the outer config.txt. A provisioned device \
      (SIGNED_BOOT=1) loads boot.img regardless, but an unprovisioned one — any \
      dev board you have not burned the key into — will not, and will fail to \
      boot. Set boot_ramdisk=1 unless every target is provisioned.
      """)
    end
  end
end
