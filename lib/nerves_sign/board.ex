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

  @doc """
  Pinned musl toolchain artifact, matching the nerves-project/toolchains
  release: `%{version: \"14.2.0\", hash: \"4D401D0\"}`. Used by
  `NervesSign.Toolchain` to fetch the same tarball the
  `nerves_toolchain_*_musl` hex package wraps.
  """
  @callback toolchain() :: %{version: String.t(), hash: String.t()}

  @doc "Default dm-crypt cipher, e.g. \"aes-xts-plain64\"."
  @callback default_cipher() :: String.t()

  @doc "Kernel CONFIG symbols that must be =y for this board to boot."
  @callback required_kernel_config() :: [String.t()]

  @doc "priv-relative dir holding this board's templates + helper sources."
  @callback priv_dir() :: Path.t()

  @doc "Default key-helper C source, priv-relative (e.g. \"boards/rpi4/helpers/unlock.c\")."
  @callback default_key_helper_source() :: Path.t()

  # --- resolution: project config overrides board defaults -------------------

  @doc """
  Absolute path to the key-helper source to compile.

  `config :nerves_sign, key_helper_source: "path/to/unlock.c"` (project-relative
  or absolute) overrides the board default shipped in nerves_sign's priv.
  """
  @spec key_helper_source(atom()) :: Path.t()
  def key_helper_source(board) do
    case Application.get_env(:nerves_sign, :key_helper_source) do
      nil ->
        Path.join(:code.priv_dir(:nerves_sign), impl(board).default_key_helper_source())

      override ->
        if Path.type(override) == :absolute,
          do: override,
          else: Path.join(File.cwd!(), override)
    end
  end

  @doc """
  The dm-crypt cipher for `which` in `[:rootfs, :data]`.

  Library default is the board default (`aes-xts-plain64`). Projects with
  existing devices override per volume, e.g.
  `config :nerves_sign, rootfs_cipher: "aes-cbc-plain"`. The same string must
  match the offline encryption in your fwup.conf and the kernel's enabled
  crypto.
  """
  @spec cipher(atom(), :rootfs | :data) :: String.t()
  def cipher(board, which) when which in [:rootfs, :data] do
    Application.get_env(:nerves_sign, :"#{which}_cipher") || impl(board).default_cipher()
  end
end
