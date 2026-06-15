defmodule NervesSign.BootImage do
  @moduledoc """
  Assemble and sign the RPi `boot.img`.

  fwup packs the kernel, the initramfs CPIO, device trees, and the inner
  config.txt/cmdline.txt into a FAT image (`boot.img`), which is then signed
  RSA-2048/SHA-256 in the Raspberry Pi bootloader format (`boot.sig`).

  Lifted from ex_verity `Rpi4SecureBoot`.
  """
  require Logger

  @doc """
  Build `boot.img` from the system images plus the prepared initramfs and
  inner txts. `opts` carries resolved paths (board fwup conf, config_txt,
  cmdline_txt, initramfs_path, rootfs_pubkey). Returns `{:ok, boot_img_path}`.
  """
  def build(system_path, fwup_conf, %{
        config_txt: config_txt,
        cmdline_txt: cmdline_txt,
        rootfs_pubkey: rootfs_pubkey,
        initramfs_path: initramfs_path
      }) do
    images_dir = Path.join(system_path, "images")
    fw_file = Path.join(Path.dirname(Briefly.create!()), "boot.fw")
    boot_img = Path.join(images_dir, "boot.img")

    env = %{
      "SOURCE" => images_dir,
      "CONFIG_TXT" => config_txt,
      "CMDLINE_TXT" => cmdline_txt,
      "ROOTFS_PUB_KEY" => Path.expand(rootfs_pubkey || ""),
      "ROOTFS" => Path.expand(initramfs_path)
    }

    with {_, 0} <- System.cmd("fwup", ["-c", "-f", fwup_conf, "-o", fw_file], env: env),
         {_, 0} <- System.cmd("fwup", ["-a", "-i", fw_file, "-t", "complete", "-d", boot_img]) do
      {:ok, boot_img}
    else
      {output, status} -> Mix.raise("fwup boot.img build failed (#{status}):\n#{output}")
    end
  end

  @doc """
  Sign `boot.img` with the RPi bootloader signature format -> `boot.sig`.
  """
  def sign(boot_img, private_key_path) do
    sig_path = Path.join(Path.dirname(boot_img), "boot.sig")
    tmp_sig = Briefly.create!()

    with {_, 0} <-
           System.cmd("openssl", [
             "dgst",
             "-sha256",
             "-sign",
             private_key_path,
             "-out",
             tmp_sig,
             boot_img
           ]),
         {shasum, 0} <- System.cmd("sha256sum", [boot_img]),
         {hexsig, 0} <- System.shell("xxd -c 4096 -p < #{tmp_sig}") do
      ts = DateTime.utc_now() |> DateTime.to_unix()
      File.write!(sig_path, "#{shasum}ts: #{ts}\nrsa2048: #{hexsig}")
      {:ok, sig_path}
    else
      other -> Mix.raise("boot.img signing failed: #{inspect(other)}")
    end
  end

  @doc "Copy the outer boot-partition config.txt/cmdline.txt next to boot.img."
  def copy_outer_txts!(boot_img, config_txt, cmdline_txt) do
    dir = Path.dirname(boot_img)
    File.cp!(config_txt, Path.join(dir, "outer_config.txt"))
    File.cp!(cmdline_txt, Path.join(dir, "outer_cmdline.txt"))
    :ok
  end
end
