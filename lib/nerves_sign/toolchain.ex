defmodule NervesSign.Toolchain do
  @moduledoc """
  Resolve the musl cross-toolchain used to build the static initramfs binaries.

  The initramfs `init` (nerves_cryptinit) and the board key helpers are built
  static-musl so no libc needs to ship in the CPIO. This toolchain is
  independent of the glibc toolchain Nerves built the system with — matching is
  tidy but not required.

  We depend on the musl toolchain as a hex package (e.g.
  `nerves_toolchain_aarch64_nerves_linux_musl`), so Nerves' own artifact
  machinery downloads, caches, and checksums it. Default to the musl
  counterpart of the project's own toolchain version; allow override via
  `config :nerves_sign, toolchain: ...`.
  """

  @doc """
  Return the cross-compiler command (`CC`) for the given board's musl
  toolchain, e.g. `"aarch64-nerves-linux-musl-gcc"`, plus the toolchain bin
  dir to put on PATH.

  TODO(milestone 2): resolve the toolchain artifact path from the Nerves
  package/cache (`Nerves.Env` / `Nerves.Artifact`), or from the configured
  override, and return `{cc, bin_dir}`.
  """
  @spec resolve(atom()) :: {cc :: String.t(), bin_dir :: Path.t()}
  def resolve(_board) do
    raise "TODO: resolve musl toolchain (see PLAN.md milestone 2)"
  end
end
