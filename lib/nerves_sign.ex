defmodule NervesSign do
  @moduledoc """
  Compile-time Nerves secure boot tooling.

  Pairs with [nerves_cryptinit](https://github.com/fhunleth/nerves_cryptinit)
  (the runtime init). nerves_sign does the build-time half: generate the
  dm-verity hash tree, build + package the initramfs (cryptinit + board key
  helper), assemble and sign `boot.img`/`boot.sig`, and put the verity root
  hash on the signed kernel cmdline.

  See `PLAN.md` for the full design and milestones.
  """
  require Logger

  @doc """
  Run the full secure-boot post-processing pipeline against the built rootfs.

  Called from the Nerves `post_processing_script`. Reads
  `config :nerves_sign` (board, keys, cipher, paths). See
  `NervesSign.PostProcess`.
  """
  def run(rootfs_path) do
    NervesSign.PostProcess.run(rootfs_path)
  end

  @doc "The board atom from config (`config :nerves_sign, board: :rpi4`)."
  @spec board() :: atom()
  def board do
    Application.get_env(:nerves_sign, :board) ||
      Mix.raise("nerves_sign: set `config :nerves_sign, board: :rpi4` in your target config")
  end
end
