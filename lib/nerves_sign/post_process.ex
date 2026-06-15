defmodule NervesSign.PostProcess do
  @moduledoc """
  The `mix firmware` post-processing entrypoint.

  Runs in the parent firmware project's context, where `config :nerves_sign`
  and `Mix.target()` are reliable and it re-runs every build — so all
  board-specific work happens here (see PLAN.md "Build flow"):

    1. build the board key helper(s)        (Toolchain + make)
    2. veritysetup format the rootfs         (DmVerity)
    3. inject verity_roothash= into cmdline   (Cmdline)
    4. assemble initramfs.cpio.gz             (Cryptinit + Initramfs)
    5. (optional) gzip the kernel
    6. build boot.img                         (BootImage)
    7. sign -> boot.sig                       (BootImage)
    8. copy outer config.txt/cmdline.txt
  """
  require Logger

  alias NervesSign.{Board, BootImage, Cmdline, Cryptinit, DmVerity, Initramfs}

  @doc "Run the pipeline against the built rootfs at `rootfs_path`."
  def run(rootfs_path) do
    board = NervesSign.board()
    _board_mod = Board.impl(board)
    cfg = Application.get_all_env(:nerves_sign)
    system_path = cfg[:system_path] || System.fetch_env!("NERVES_SYSTEM")

    Logger.info("nerves_sign: post-processing for board #{inspect(board)}")

    # 2. hash tree
    {root_hash, _offset} =
      DmVerity.generate_tree!(Map.new(cfg[:verity] || []), rootfs_path)

    # 3. cmdline with the trust anchor
    _inner_cmdline = Cmdline.with_roothash(board_file(board, "cmdline.txt"), root_hash)

    # 1/4. initramfs (cryptinit + helper + conf)  -- TODO milestones 2-3
    _init = fn -> Cryptinit.build(board) end
    _cpio = fn spec -> Initramfs.assemble(spec) end

    # 6/7/8. boot.img + sign + outer txts          -- TODO wiring in milestone 4
    _ = {BootImage, system_path}

    Logger.warning("nerves_sign: pipeline wiring is staged (see PLAN.md milestones 2-4)")
    :ok
  end

  defp board_file(board, name) do
    Path.join([:code.priv_dir(:nerves_sign), Board.impl(board).priv_dir(), name])
  end
end
