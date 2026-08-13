defmodule NervesSign.PostProcess do
  @moduledoc """
  The `mix firmware` post-processing entrypoint. Runs in the firmware project's
  context against the built rootfs:

    1. veritysetup format the rootfs           (DmVerity)
    2. resolve musl toolchain                   (Toolchain)
    3. build cryptinit init                     (Cryptinit)
    4. inject verity_roothash= into cmdline     (Cmdline)
    5. validate the config against boot.img     (Preflight)
    6. build helper + assemble initramfs.cpio.gz (Initramfs)
    7. build boot.img                           (BootImage)
    8. sign -> boot.sig                          (BootImage)
    9. copy outer config.txt/cmdline.txt
  """
  require Logger

  alias NervesSign.Boards.RPi.BootImage

  alias NervesSign.{
    Cmdline,
    Cryptinit,
    DmVerity,
    Initramfs,
    Paths,
    Preflight,
    Toolchain
  }

  @doc "Run the pipeline against the built rootfs at `rootfs_path`."
  def run(rootfs_path) do
    board = NervesSign.board()
    cfg = Application.get_all_env(:nerves_sign)
    sb = Map.new(cfg[:rpi4_secure_boot] || [])
    app_dir = System.get_env("NERVES_APP", File.cwd!())
    system_path = cfg[:system_path] || System.fetch_env!("NERVES_SYSTEM")

    Logger.info("nerves_sign: post-processing #{rootfs_path} for board #{inspect(board)}")

    # 1. hash tree
    {root_hash, _offset} = DmVerity.generate_tree!(Map.new(cfg[:verity] || []), rootfs_path)

    # 2/3. toolchain + cryptinit
    toolchain = Toolchain.resolve(board)
    init = Cryptinit.build(toolchain)

    # 4. inner cmdline with the trust anchor
    cmdline_src = Paths.resolve(sb[:cmdline_txt_path] || "config/rpi4/cmdline.txt", app_dir)
    rendered_cmdline = Cmdline.with_roothash(cmdline_src, root_hash)
    inner_cmdline = Briefly.create!()
    File.write!(inner_cmdline, rendered_cmdline)

    # 5. everything that would only surface as a silently unverified device
    config_txt = Paths.resolve(sb[:config_txt_path] || "config/rpi4/config.txt", app_dir)

    boot_fwup =
      Paths.project_or_board(
        board,
        sb[:boot_fwup_conf],
        app_dir,
        "config/rpi4/boot_fwup.conf",
        "boot_fwup.conf"
      )

    :ok =
      Preflight.check!(board, %{
        board: board,
        cmdline: rendered_cmdline,
        config_txt: config_txt,
        boot_fwup_conf: boot_fwup,
        app_dir: app_dir
      })

    # 6. initramfs
    conf =
      Paths.project_or_board(
        board,
        sb[:initramfs_conf],
        app_dir,
        "config/rpi4/initramfs.conf",
        "initramfs.conf"
      )

    cpio =
      Initramfs.assemble(%{board: board, toolchain: toolchain, init: init, initramfs_conf: conf})

    # 7. boot.img
    {:ok, boot_img} =
      BootImage.build(system_path, boot_fwup, %{
        config_txt: config_txt,
        cmdline_txt: inner_cmdline,
        rootfs_pubkey: sb[:rootfs_public_key_path],
        initramfs_path: cpio
      })

    Logger.info("nerves_sign: built #{boot_img} (#{File.stat!(boot_img).size} bytes)")

    # 8. sign
    {:ok, sig} = BootImage.sign(boot_img, Paths.resolve(sb[:private_key_path], app_dir))
    Logger.info("nerves_sign: signed -> #{sig}")

    # 9. outer txts
    BootImage.copy_outer_txts!(boot_img, config_txt, cmdline_src)
    Logger.info("nerves_sign: done")
    :ok
  end
end
