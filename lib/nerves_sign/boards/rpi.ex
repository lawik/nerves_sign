defmodule NervesSign.Boards.RPi do
  @moduledoc """
  What every Raspberry Pi board has in common.

  The Pi family shares far more than it differs on. The boot firmware contract
  (`NervesSign.Boards.RPi.Preflight`), the signed-ramdisk scheme and its
  `rpi-eeprom-digest` signature format (`NervesSign.Boards.RPi.BootImage`), the
  customer-OTP key helper in `priv/boards/rpi/helpers/`, and the configuration
  below are all properties of *a Pi*, not of a Pi 4.

  What is genuinely per-board lives in the board module and its own priv dir:
  the device trees and firmware blobs, the toolchain pin, the partition layout,
  and the fwup configs that name them.

  None of this transfers off the Pi. A board from another vendor implements
  `NervesSign.Board` from scratch.
  """
  require Logger

  @key :rpi_secure_boot
  @legacy_key :rpi4_secure_boot

  @doc """
  The `#{inspect(@key)}` block from the project config, as a map.

  Accepts the old `#{inspect(@legacy_key)}` name with a warning: the settings
  in it — signing key, config.txt and cmdline.txt paths — were never specific
  to the Pi 4.
  """
  @spec secure_boot_config() :: map()
  def secure_boot_config do
    current = Application.get_env(:nerves_sign, @key)
    legacy = Application.get_env(:nerves_sign, @legacy_key)

    case {current, legacy} do
      {nil, nil} ->
        %{}

      {nil, legacy} ->
        Logger.warning(
          "nerves_sign: `config :nerves_sign, #{@legacy_key}:` is deprecated — " <>
            "rename it to `#{@key}:`. These settings apply to every Pi board, " <>
            "not just the Pi 4."
        )

        Map.new(legacy)

      {current, nil} ->
        Map.new(current)

      {current, _legacy} ->
        Logger.warning(
          "nerves_sign: both `#{@key}:` and the deprecated `#{@legacy_key}:` are " <>
            "set. Using `#{@key}:` and ignoring the other; delete it."
        )

        Map.new(current)
    end
  end
end
