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
    check_overlays!(directives, packed, config_txt, fwup_conf)
    :ok
  end

  @doc """
  Extract the directives we care about from a `config.txt` body:
  `%{kernel: name, initramfs: name, cmdline: name, boot_ramdisk: "1"}`. Absent
  keys are absent from the map.
  """
  @spec parse(String.t()) :: %{atom() => String.t() | [String.t()]}
  def parse(body) do
    body
    |> String.split("\n")
    |> Enum.map(&(&1 |> String.split("#", parts: 2) |> hd() |> String.trim()))
    |> Enum.reduce(%{dtoverlays: []}, &collect_directive/2)
    |> Map.update!(:dtoverlays, &Enum.reverse/1)
  end

  defp collect_directive(line, acc) do
    case line do
      # `initramfs <file> [<address>|followkernel]` — space-separated, not `=`.
      "initramfs " <> rest ->
        case String.split(rest) do
          [file | _] -> Map.put(acc, :initramfs, file)
          [] -> acc
        end

      # `dtoverlay=name`, `dtoverlay=name,param=value`, or a bare `dtoverlay=`
      # which only terminates the previous overlay's parameter list.
      "dtoverlay=" <> rest ->
        case rest |> String.split(",", parts: 2) |> hd() |> String.trim() do
          "" -> acc
          name -> Map.update!(acc, :dtoverlays, &[name | &1])
        end

      _ ->
        case String.split(line, "=", parts: 2) do
          [k, v] when k in ~w(kernel cmdline boot_ramdisk) ->
            Map.put(acc, String.to_existing_atom(k), String.trim(v))

          # dtparam= applies to the base device tree and needs no overlay file.
          _ ->
            acc
        end
    end
  end

  # Under stock Nerves the boot partition carries the whole overlays/ directory
  # from rpi-firmware, so `dtoverlay=anything` just works. Inside a signed
  # boot.img only what the fwup config enumerates exists, and a missing overlay
  # is silent: the firmware warns on the UART and boots anyway, leaving a device
  # with no driver for the peripheral. You cannot drop the file on afterwards
  # either — that invalidates boot.sig.
  defp check_overlays!(directives, packed, config_txt, fwup_conf) do
    missing =
      directives
      |> Map.get(:dtoverlays, [])
      |> Enum.map(&overlay_file/1)
      |> Enum.reject(&MapSet.member?(packed, &1))
      |> Enum.uniq()

    if missing != [] do
      example = hd(missing)

      Mix.raise("""
      nerves_sign: #{config_txt} requests overlays that are not packed into boot.img
      by #{fwup_conf}:

        #{Enum.join(missing, "\n  ")}

      Under secure boot the signed image carries only the overlays the fwup config
      names, and you cannot add one to the boot partition afterwards without
      invalidating boot.sig. The firmware would boot anyway and simply not apply
      them, leaving the driver missing at runtime with no error anywhere.

      Add each to #{Path.basename(fwup_conf)}, e.g.

          file-resource #{Path.basename(example)} { host-path = "${SOURCE}/rpi-firmware/#{example}" }

      and a matching fat_write into "#{example}".
      """)
    end
  end

  defp overlay_file(name) do
    if String.ends_with?(name, ".dtbo"),
      do: "overlays/#{name}",
      else: "overlays/#{name}.dtbo"
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
