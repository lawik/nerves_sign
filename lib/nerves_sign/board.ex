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

  @doc "Kernel CONFIG symbols that must be =y for this board to boot."
  @callback required_kernel_config() :: [String.t()]

  @doc "priv-relative dir holding this board's templates + helper sources."
  @callback priv_dir() :: Path.t()

  @doc """
  Directory name under the project's `config/` holding the files the developer
  owns, e.g. `"rpi4"` for `config/rpi4/`.

  `mix nerves_sign.gen.<board>` writes them there and post-processing reads
  them back, so the two must agree. Declared rather than derived from
  `c:priv_dir/0`: these paths exist on developers' disks, and renaming an
  internal directory must not silently move them.
  """
  @callback config_dir() :: String.t()

  @doc """
  Default key-helper C source, priv-relative (e.g. `"boards/rpi/helpers/unlock.c"`).

  Boards that share a key interface should share the source: every Pi reads
  customer OTP through the same VideoCore mailbox, so they all point at
  `boards/rpi/`, not at a per-board copy.
  """
  @callback default_key_helper_source() :: Path.t()

  @doc """
  Validate the board's boot firmware contract before anything is signed.

  This is the half of preflight that cannot be shared: how a ROM or firmware
  locates the kernel, the initramfs and the cmdline is board-specific to the
  bone. The RPi firmware parses `config.txt` out of the FAT boot image; an
  i.MX HAB/TrustZone chain validates a signed container and has no `config.txt`
  at all. `NervesSign.Preflight` runs the board-agnostic cryptinit cmdline
  checks and then calls this.

  `ctx` is the resolved build context. Read the keys you need and ignore the
  rest — it is a map precisely so new keys can be added without breaking
  boards. Currently supplied:

    * `:board` - the board atom in play (`:rpi4` and `:cm4` share a module)
    * `:cmdline` - the rendered kernel cmdline, root hash already injected
    * `:config_txt` - resolved path to the project's boot config, if the board
      has such a thing
    * `:boot_fwup_conf` - resolved path to the boot image's fwup config
    * `:app_dir` - the firmware project root

  Raise (via `Mix.raise/1`) on anything that would not boot; log a warning for
  the merely suspicious. Return `:ok`. A board with nothing to check should say
  so explicitly — in secure boot, "nothing to validate" is a decision worth
  writing down rather than a default worth inheriting.
  """
  @callback preflight!(ctx :: map()) :: :ok

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
end
