defmodule Mix.Tasks.NervesSign.PostProcess do
  @shortdoc "Run the secure-boot pipeline on a built rootfs (post-processing hook)"
  @moduledoc """
  The Elixir half of `priv/nerves_sign/post_process`:

      mix nerves_sign.post_process <rootfs-image>

  Invoked by the shell hook Nerves runs after assembling the rootfs, with
  MIX_TARGET/MIX_ENV inherited from the `mix firmware` that triggered it.

  A mix task rather than `mix run -e` for a reason that cost a build to learn:
  nerves_bootstrap aliases `run` under any non-host MIX_TARGET into a
  "cannot run target code on host" warning — and exits 0, so a `set -e` hook
  sails past it and fwup later fails on the boot.img that was never built.
  Flipping the hook to MIX_TARGET=host instead loses the project's target
  config, where `config :nerves_sign` lives. Custom tasks are not aliased, so
  this runs under the caller's target env with the right config loaded.
  """
  use Mix.Task

  @impl true
  def run([fs_path]) do
    # Everything is already compiled by the `mix firmware` that invoked the
    # hook, so this is a load-paths no-op in practice. NervesSign.run executes
    # host-side build tooling only; no target application is started.
    Mix.Task.run("compile")
    NervesSign.run(fs_path)
  end

  def run(_), do: Mix.raise("usage: mix nerves_sign.post_process <rootfs-image>")
end
