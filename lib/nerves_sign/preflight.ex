defmodule NervesSign.Preflight do
  @moduledoc """
  Validate the build *before* it gets signed.

  The failure mode this exists to prevent is silent: a boot config that never
  loads the initramfs still builds, still signs, and still passes a bootloader
  signature check — the firmware just boots the kernel without cryptinit, so
  dm-verity never runs and the root hash on the signed cmdline is never read.
  Nothing downstream notices; the device either fails to mount its rootfs or
  comes up unverified.

  There are two contracts here, and the split is what keeps this from being
  RPi-shaped forever:

    * **The cryptinit contract** — what the kernel cmdline has to carry for the
      init we ship to work at all. That is a property of `nerves_cryptinit`,
      not of any board, so every board gets it and it lives in this module.

    * **The boot firmware contract** — how a particular ROM or firmware finds
      the kernel, the initramfs and the cmdline. This is where boards diverge
      completely: the RPi firmware parses `config.txt` out of a FAT image,
      while an i.MX HAB or TrustZone chain validates a signed container and has
      no `config.txt` anywhere. So it lives behind
      `c:NervesSign.Board.preflight!/1`, in the board.
  """

  alias NervesSign.Board

  @doc """
  Run both contracts for `board`.

  `ctx` is the resolved build context. Keys the board half may read are
  documented on `c:NervesSign.Board.preflight!/1`; this half needs only
  `:cmdline`, the rendered kernel cmdline. Raises on anything that would not
  boot; boards may log warnings for the merely suspicious.
  """
  @spec check!(atom(), map()) :: :ok
  def check!(board, ctx) do
    check_cmdline!(ctx.cmdline)
    :ok = Board.impl(board).preflight!(ctx)
    :ok
  end

  @doc """
  Check a rendered kernel cmdline against what `nerves_cryptinit` requires.

  Board-agnostic: these come from cryptinit's own `main.c`, so they hold for
  any board that boots the init we package.

  Raises when `root=` is missing (cryptinit calls that fatal) or names a device
  mapper node: cryptinit *creates* `/dev/dm-N` from `root=`, so pointing at one
  is circular and the device will never appear. Warns when `ro` is absent,
  since the verity device is read-only and a read-write mount of it fails.
  """
  @spec check_cmdline!(String.t()) :: :ok
  def check_cmdline!(cmdline) do
    params = String.split(cmdline)
    root = Enum.find_value(params, fn p -> match_value(p, "root=") end)

    cond do
      is_nil(root) ->
        Mix.raise("""
        nerves_sign: the inner cmdline has no `root=`.

        cryptinit exits fatally without it. Point it at the partition holding \
        the verity-formatted rootfs, e.g. root=/dev/mmcblk0p2
        """)

      String.starts_with?(root, "/dev/dm-") or String.starts_with?(root, "/dev/mapper/") ->
        Mix.raise("""
        nerves_sign: the inner cmdline sets `root=#{root}`, a device-mapper node.

        That is cryptinit's output, not its input: it reads root= to find the \
        backing partition and creates the dm device itself. Point root= at the \
        real partition, e.g. root=/dev/mmcblk0p2
        """)

      true ->
        :ok
    end

    unless "ro" in params do
      require Logger

      Logger.warning(
        "nerves_sign: the inner cmdline has no `ro`. The dm-verity device is " <>
          "read-only, so a read-write mount of it fails. Add `ro`."
      )
    end

    :ok
  end

  defp match_value(param, key) do
    case String.split(param, key, parts: 2) do
      ["", value] -> value
      _ -> nil
    end
  end
end
