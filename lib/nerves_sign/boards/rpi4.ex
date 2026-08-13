defmodule NervesSign.Boards.RPi4 do
  @moduledoc """
  Raspberry Pi 4 / CM4 board support.

  Lifted from ex_verity's RPi4 secure boot, adapted for nerves_cryptinit:
  the boot partition carries only `boot.img` + `boot.sig` + tiny outer txts
  (no loose kernel/firmware/dtbs), the partition returns to the stock size,
  and the init is cryptinit (root hash on the signed cmdline).
  """
  @behaviour NervesSign.Board

  @impl true
  def toolchain_triple, do: "aarch64-nerves-linux-musl"

  @impl true
  def toolchain, do: %{version: "14.2.0", hash: "4D401D0"}

  @impl true
  # cryptinit's default. Requires CRYPTO_XTS=y in the kernel.
  def default_cipher, do: "aes-xts-plain64"

  @impl true
  def required_kernel_config do
    ~w(
      CONFIG_BLK_DEV_INITRD
      CONFIG_BLK_DEV_DM
      CONFIG_DM_VERITY
      CONFIG_DM_CRYPT
      CONFIG_CRYPTO_SHA256
      CONFIG_CRYPTO_AES
      CONFIG_CRYPTO_XTS
    )
  end

  @impl true
  def priv_dir, do: "boards/rpi4"

  @impl true
  # Shared with every Pi: the customer OTP rows are read through the VideoCore
  # mailbox, which is a family interface, not a board one.
  def default_key_helper_source, do: "boards/rpi/helpers/unlock.c"

  @impl true
  defdelegate preflight!(ctx), to: NervesSign.Boards.RPi.Preflight, as: :check!
end
