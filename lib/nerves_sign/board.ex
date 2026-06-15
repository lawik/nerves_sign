defmodule NervesSign.Board do
  @moduledoc """
  Behaviour for a supported board.

  A board is selected with `config :nerves_sign, board: :rpi4` (decoupled from
  the user's `MIX_TARGET` name, since one project may have several rpi4-derived
  targets). Each board supplies the bits that differ: the boot.img fwup config,
  the musl toolchain triple, the default cipher, the key-helper sources, and the
  kernel CONFIG it requires.
  """

  @doc "Module implementing a board atom, or raises if unsupported."
  @spec impl(atom()) :: module()
  def impl(:rpi4), do: NervesSign.Boards.RPi4
  def impl(:cm4), do: NervesSign.Boards.RPi4
  def impl(other), do: Mix.raise("nerves_sign: unsupported board #{inspect(other)}")

  @doc "musl toolchain triple, e.g. \"aarch64-nerves-linux-musl\"."
  @callback toolchain_triple() :: String.t()

  @doc "Default dm-crypt cipher, e.g. \"aes-xts-plain64\"."
  @callback default_cipher() :: String.t()

  @doc "Kernel CONFIG symbols that must be =y for this board to boot."
  @callback required_kernel_config() :: [String.t()]

  @doc "priv-relative dir holding this board's templates + helper sources."
  @callback priv_dir() :: Path.t()
end
