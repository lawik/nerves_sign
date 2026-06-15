defmodule NervesSign.Cryptinit do
  @moduledoc """
  Build the nerves_cryptinit `init` binary from source (static, musl).

  We consume the upstream `nerves_cryptinit` (a git/hex dep), build it from
  source rather than trusting a prebuilt — and because it must live inside the
  signed boot.img anyway. The board-agnostic `init` can be built at compile
  time via elixir_make; this module is the post-process fallback/driver that
  builds it with the resolved musl `$CC`.
  """

  @doc """
  Build cryptinit's `init` and return the path to the static binary.

  TODO(milestone 2): locate the dep source (`deps/nerves_cryptinit/src`), run
  its Makefile with `CC=<musl-gcc> CFLAGS=... -static` via
  `NervesSign.Toolchain.resolve/1`, return the `init` path.
  """
  @spec build(atom()) :: Path.t()
  def build(_board) do
    raise "TODO: build cryptinit init (see PLAN.md milestone 2)"
  end
end
