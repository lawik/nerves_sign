defmodule Mix.Tasks.NervesSign.Gen.Rpi4 do
  @shortdoc "Generate RPi4/CM4 secure boot scaffold into your firmware project"
  @moduledoc """
  Copies the project-owned secure-boot config into your firmware project so you
  own it (no fork of nerves_sign needed to adjust your system):

      mix nerves_sign.gen.rpi4

  Generates:
    - config/rpi4/boot_fwup.conf     inner boot.img layout
    - config/rpi4/config.txt         inner RPi config
    - config/rpi4/cmdline.txt        inner cmdline (verity_roothash= injected at build)
    - config/rpi4/initramfs.conf     cryptinit config
    - priv/nerves_sign/post_process  post-processing hook

  Then wire it up in your target config (see the printed instructions).
  """
  use Mix.Task

  @board :rpi4

  # Copied from the board's priv dir into the project, keeping the same
  # relative layout. The destination directory comes from the board so this and
  # the post-processing that reads them back cannot drift apart.
  @files ~w(
    fwup.conf
    fwup_include/fwup-common.conf
    boot_fwup.conf
    config.txt
    cmdline.txt
    initramfs.conf
  )

  @impl Mix.Task
  def run(_args) do
    Application.ensure_loaded(:nerves_sign)
    priv = Path.join(:code.priv_dir(:nerves_sign), NervesSign.Boards.RPi4.priv_dir())

    Mix.shell().info("Generating RPi4/CM4 secure boot files...\n")

    for name <- @files do
      copy(Path.join(priv, name), NervesSign.Paths.project_config(@board, name))
    end

    # Post-processing bridge script
    bridge = Path.join(:code.priv_dir(:nerves_sign), "post_process")
    copy(bridge, "priv/nerves_sign/post_process")
    File.chmod("priv/nerves_sign/post_process", 0o755)

    Mix.shell().info("""

    Files generated. Add to your target config (e.g. config/rpi4.exs):

        config :nerves_sign,
          board: :rpi4,
          verity: [block_size: 4096],
          # Cipher defaults to aes-xts-plain64. Override per volume to keep an
          # existing device scheme (must match your fwup offline encryption and
          # the kernel's enabled crypto):
          # rootfs_cipher: "aes-cbc-plain",
          # Override the OTP/key helper source if you need your own:
          # key_helper_source: "priv/secure_boot/unlock.c",
          rpi_secure_boot: [
            private_key_path: System.fetch_env!("NERVES_SIGN_BOOT_PRIVATE_KEY_PATH"),
            config_txt_path: "config/rpi4/config.txt",
            cmdline_txt_path: "config/rpi4/cmdline.txt"
          ]

        config :nerves, :firmware,
          fwup_conf: "config/rpi4/fwup.conf",
          post_processing_script: Path.expand("priv/nerves_sign/post_process")

    Your kernel must have these built in (=y): #{Enum.join(NervesSign.Boards.RPi4.required_kernel_config(), ", ")}.
    All generated files are yours to edit.
    """)
  end

  defp copy(src, dest) do
    if File.exists?(dest) do
      Mix.shell().info("  skipping #{dest} (exists)")
    else
      File.mkdir_p!(Path.dirname(dest))
      File.cp!(src, dest)
      Mix.shell().info("  created #{dest}")
    end
  end
end
