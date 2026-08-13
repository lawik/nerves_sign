defmodule NervesSign.Boards.RPi.BootImage do
  @moduledoc """
  Assemble and sign the Raspberry Pi `boot.img`.

  Family-wide, not per board: the signed-ramdisk scheme is a property of the Pi
  bootloader EEPROM, so every Pi that supports secure boot (4, CM4, 5, CM5)
  uses this same shape. fwup packs the kernel, the initramfs CPIO, device trees
  and the inner config.txt/cmdline.txt into a FAT image, which is then signed
  RSA-2048/SHA-256 in the `rpi-eeprom-digest` format the bootloader expects.
  Which files go in is the board's business, and lives in its fwup config.

  Nothing here transfers off the Pi. Another vendor's secure boot signs a
  different container with a different tool into a different format.

  Lifted from ex_verity `Rpi4SecureBoot`.
  """

  @doc """
  Build `boot.img` from the system images plus the prepared initramfs and
  inner txts. `opts` carries resolved paths (config_txt, cmdline_txt,
  initramfs_path). Returns `{:ok, boot_img_path}`.
  """
  def build(system_path, fwup_conf, %{
        config_txt: config_txt,
        cmdline_txt: cmdline_txt,
        initramfs_path: initramfs_path
      }) do
    images_dir = Path.join(system_path, "images")
    fw_file = Path.join(Path.dirname(Briefly.create!()), "boot.fw")
    boot_img = Path.join(images_dir, "boot.img")

    env = %{
      "SOURCE" => images_dir,
      "CONFIG_TXT" => config_txt,
      "CMDLINE_TXT" => cmdline_txt,
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

    # stderr is captured throughout: openssl explains a bad key there, and
    # without it a failure raises an exit code and nothing to act on.
    with {_, 0} <-
           System.cmd(
             "openssl",
             ["dgst", "-sha256", "-sign", private_key_path, "-out", tmp_sig, boot_img],
             stderr_to_stdout: true
           ),
         {shasum, 0} <- System.cmd("sha256sum", [boot_img], stderr_to_stdout: true),
         {hexsig, 0} <- System.shell("xxd -c 4096 -p < #{tmp_sig}", stderr_to_stdout: true) do
      # rpi-eeprom-digest format: the first line is the bare hex digest.
      # sha256sum appends "  <filename>", which the bootloader rejects.
      digest = shasum |> String.split() |> hd()
      ts = DateTime.utc_now() |> DateTime.to_unix()
      File.write!(sig_path, "#{digest}\nts: #{ts}\nrsa2048: #{hexsig}")
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
