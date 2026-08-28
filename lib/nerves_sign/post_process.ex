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
    sb = NervesSign.Boards.RPi.secure_boot_config()
    app_dir = System.get_env("NERVES_APP", File.cwd!())
    system_path = cfg[:system_path] || System.fetch_env!("NERVES_SYSTEM")

    Logger.info("nerves_sign: post-processing #{rootfs_path} for board #{inspect(board)}")

    # 1. hash tree
    {root_hash, _offset} = DmVerity.generate_tree!(Map.new(cfg[:verity] || []), rootfs_path)

    # 2/3. toolchain + cryptinit
    toolchain = Toolchain.resolve(board)
    init = Cryptinit.build(toolchain)

    # 4. inner cmdline with the trust anchor
    cmdline_src =
      Paths.resolve(sb[:cmdline_txt_path] || Paths.project_config(board, "cmdline.txt"), app_dir)

    rendered_cmdline = Cmdline.with_roothash(cmdline_src, root_hash)
    inner_cmdline = Briefly.create!()
    File.write!(inner_cmdline, rendered_cmdline)

    # 5. everything that would only surface as a silently unverified device
    config_txt =
      Paths.resolve(sb[:config_txt_path] || Paths.project_config(board, "config.txt"), app_dir)

    boot_fwup =
      Paths.project_file!(
        sb[:boot_fwup_conf],
        app_dir,
        Paths.project_config(board, "boot_fwup.conf"),
        "nerves_sign.gen.#{NervesSign.Board.impl(board).config_dir()}"
      )

    Logger.info("nerves_sign: boot fwup config #{boot_fwup}")

    :ok =
      Preflight.check!(board, %{
        board: board,
        cmdline: rendered_cmdline,
        config_txt: config_txt,
        boot_fwup_conf: boot_fwup,
        app_dir: app_dir
      })

    # 6. initramfs. No cryptinit config means no encryption: cryptinit treats
    # a missing /etc/initramfs.conf as "verity only", and dm-verity reads
    # nothing from it. Absence is a choice here (gen --no-encryption), not a
    # gap to paper over with our copy.
    #
    # Config-first: `rpi_secure_boot: [cryptinit: [rootfs_key: ..., ...]]`
    # declares the settings in the project's target config, where facts like a
    # fleet's key scheme belong — a regenerated initramfs.conf cannot reset
    # them there. When settings are configured, a conventional initramfs.conf
    # on disk is a hard error rather than a silently losing competitor.
    conf = resolve_initramfs_conf(sb, app_dir, board)

    Logger.info(
      "nerves_sign: " <>
        case conf do
          nil -> "no cryptinit config; verity only"
          settings when is_list(settings) -> "cryptinit config from application config"
          path -> "cryptinit config #{path}"
        end
    )

    cpio =
      Initramfs.assemble(%{board: board, toolchain: toolchain, init: init, initramfs_conf: conf})

    # 7. boot.img
    {:ok, boot_img} =
      BootImage.build(system_path, boot_fwup, %{
        config_txt: config_txt,
        cmdline_txt: inner_cmdline,
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

  @doc """
  Decide where the cryptinit config comes from.

  Returns the keyword settings from `rpi_secure_boot: [cryptinit: ...]`, a
  path to an initramfs.conf, or `nil` for a verity-only device.

  Config-first: declared settings are authoritative, and a conventional
  `config/<board>/initramfs.conf` existing alongside them is a hard error
  rather than a silently losing competitor — that file is scaffold territory
  (`mix nerves_sign.gen` writes it with fresh-fleet defaults), and fleet
  facts like a key scheme must not be resettable by regenerating a file.
  """
  @spec resolve_initramfs_conf(keyword(), Path.t(), atom()) :: keyword() | Path.t() | nil
  def resolve_initramfs_conf(sb, app_dir, board) do
    conventional = Path.join(app_dir, Paths.project_config(board, "initramfs.conf"))

    case {sb[:cryptinit], sb[:initramfs_conf]} do
      {nil, nil} ->
        if File.exists?(conventional), do: conventional, else: nil

      {nil, configured} ->
        Paths.resolve(configured, app_dir)

      {settings, nil} when is_list(settings) ->
        if File.exists?(conventional) do
          Mix.raise("""
          nerves_sign: cryptinit settings are declared in config \
          (`rpi_secure_boot: [cryptinit: ...]`), but #{conventional} also \
          exists. The config is authoritative — delete the file (it may \
          have been regenerated by `mix nerves_sign.gen`), or drop the \
          `cryptinit` config to go back to file-based settings.\
          """)
        end

        settings

      {_, _} ->
        Mix.raise(
          "nerves_sign: both `cryptinit` settings and `initramfs_conf` are configured; pick one"
        )
    end
  end
end
