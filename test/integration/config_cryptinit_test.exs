defmodule NervesSign.Integration.ConfigCryptinitTest do
  @moduledoc """
  The config-first cryptinit path, end to end: settings declared in
  `rpi_secure_boot: [cryptinit: ...]` — no initramfs.conf file anywhere in the
  project — must come out the other side of the real pipeline as
  `/etc/initramfs.conf` inside the signed boot.img, byte-exact.

  This is the mechanism a fleet's key scheme rides on (entryfy's raw-key/
  aes-cbc-plain devices), so "the rendering unit test passes" is not enough:
  what matters is what the initramfs cryptinit actually reads contains.
  """
  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag timeout: 300_000

  tools = ~w(veritysetup mksquashfs fwup mcopy mtype cpio gzip make)
  missing = Enum.reject(tools, &System.find_executable/1)

  if missing != [] do
    @moduletag skip: "missing host tools: #{Enum.join(missing, ", ")}"
  end

  unless File.dir?(Path.join(Mix.Project.deps_path(), "nerves_cryptinit/src")) do
    @moduletag skip: "nerves_cryptinit dep not fetched (run mix deps.get)"
  end

  @dtbs ~w(bcm2711-rpi-4-b.dtb bcm2711-rpi-400.dtb bcm2711-rpi-cm4.dtb ramoops.dtb)
  @overlays ~w(overlay_map.dtb vc4-kms-v3d.dtbo vc4-kms-v3d-pi4.dtbo dwc2.dtbo)

  @cryptinit [
    rootfs_key:
      "cmd:/usr/sbin/bootstrap-or-derive --raw /dev/mmcblk0p2 /dev/mmcblk0p4 aes-cbc-plain",
    rootfs_cipher: "aes-cbc-plain"
  ]

  setup_all do
    root = Path.join(System.tmp_dir!(), "ns_cfgconf_#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    on_exit(fn -> File.rm_rf(root) end)

    sys = fixture_system!(root)
    app = fixture_app!(root)
    rootfs = fixture_rootfs!(root)

    key = Path.join(root, "key.pem")
    pub = Path.join(root, "key.pub.pem")
    :ok = BodgeRPiBootTest.generate_keys(key, pub)

    configure!(sys, app, key)
    :ok = NervesSign.PostProcess.run(rootfs)

    {:ok, root: root, sys: sys}
  end

  test "the settings land in the signed boot.img as /etc/initramfs.conf", c do
    conf = initramfs_conf_from(Path.join(c.sys, "images/boot.img"))

    assert conf == NervesSign.Initramfs.render_conf(@cryptinit)

    # And spelled out, because these exact strings are what cryptinit parses:
    assert conf =~
             "rootfs_key = cmd:/usr/sbin/bootstrap-or-derive --raw /dev/mmcblk0p2 /dev/mmcblk0p4 aes-cbc-plain\n"

    assert conf =~ "rootfs_cipher = aes-cbc-plain\n"
  end

  test "the helper the settings name is in the initramfs too", c do
    names = cpio_names(Path.join(c.sys, "images/boot.img"))
    assert "usr/sbin/bootstrap-or-derive" in names
    assert "etc/initramfs.conf" in names
  end

  # --- pulling the initramfs back out of the built image ---------------------

  defp initramfs_conf_from(boot_img) do
    {_, content} =
      boot_img |> cpio_entries() |> Enum.find(fn {name, _} -> name == "etc/initramfs.conf" end)

    content
  end

  defp cpio_names(boot_img), do: boot_img |> cpio_entries() |> Enum.map(&elem(&1, 0))

  defp cpio_entries(boot_img) do
    {gz, 0} =
      System.cmd("mtype", ["-i", boot_img, "::rootfs.cpio.gz"], env: [{"MTOOLS_SKIP_CHECK", "1"}])

    # Concatenated gzip members (device nodes + main archive); zcat handles
    # what :zlib.gunzip cannot.
    tmp = Path.join(System.tmp_dir!(), "ns_cfgconf_#{System.unique_integer([:positive])}.cpio.gz")
    File.write!(tmp, gz)
    {data, 0} = System.cmd("zcat", [tmp])
    File.rm!(tmp)
    parse_newc(data, [])
  end

  defp parse_newc(<<"070701", _::binary>> = data, acc) do
    <<header::binary-110, rest::binary>> = data
    namesize = header |> binary_part(94, 8) |> String.to_integer(16)
    filesize = header |> binary_part(54, 8) |> String.to_integer(16)

    name = binary_part(rest, 0, namesize - 1)
    rest = skip_pad(binary_part(rest, namesize, byte_size(rest) - namesize), 110 + namesize)

    <<content::binary-size(filesize), rest::binary>> = rest
    rest = skip_pad(rest, filesize)

    if name == "TRAILER!!!",
      do: parse_newc(rest, acc),
      else: parse_newc(rest, [{name, content} | acc])
  end

  defp parse_newc(<<0, rest::binary>>, acc), do: parse_newc(rest, acc)
  defp parse_newc(<<>>, acc), do: Enum.reverse(acc)

  defp skip_pad(bin, consumed) do
    case rem(consumed, 4) do
      0 -> bin
      r -> binary_part(bin, 4 - r, byte_size(bin) - (4 - r))
    end
  end

  # --- fixtures, the shape firmware_test.exs uses ----------------------------

  defp filler(seed, size) do
    :sha256 |> :crypto.hash(seed) |> :binary.copy(div(size, 32) + 1) |> binary_part(0, size)
  end

  defp fixture_system!(root) do
    sys = Path.join(root, "system")
    images = Path.join(sys, "images")
    File.mkdir_p!(Path.join(images, "rpi-firmware/overlays"))
    File.mkdir_p!(Path.join(images, "fwup_include"))
    File.write!(Path.join(images, "fwup_include/provisioning.conf"), "\n")

    for f <- @dtbs, do: File.write!(Path.join(images, f), filler(f, 4_096))
    File.write!(Path.join(images, "Image"), filler("Image", 1_000_000))
    File.write!(Path.join(images, "rpi-firmware/fixup4x.dat"), filler("fixup4x", 2_048))
    File.write!(Path.join(images, "rpi-firmware/start4x.elf"), filler("start4x", 100_000))

    for f <- @overlays,
        do: File.write!(Path.join(images, "rpi-firmware/overlays/#{f}"), filler(f, 1_024))

    sys
  end

  defp fixture_app!(root) do
    app = Path.join(root, "app")
    conf = Path.join(app, "config/rpi4")
    File.mkdir_p!(conf)

    priv = Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4"])

    # The scaffold minus initramfs.conf: settings come from config, and the
    # resolver treats a conventional file alongside them as an error.
    for name <- ~w(boot_fwup.conf config.txt cmdline.txt) do
      File.cp!(Path.join(priv, name), Path.join(conf, name))
    end

    app
  end

  defp fixture_rootfs!(root) do
    src = Path.join(root, "rootfs_src")
    File.mkdir_p!(src)
    File.write!(Path.join(src, "hello.txt"), "config cryptinit fixture\n")
    out = Path.join(root, "rootfs.squashfs")

    {_, 0} =
      System.cmd("mksquashfs", [src, out, "-quiet", "-no-progress"], stderr_to_stdout: true)

    out
  end

  defp configure!(sys, app, key) do
    prev = Application.get_all_env(:nerves_sign)
    prev_app = System.get_env("NERVES_APP")

    Application.put_env(:nerves_sign, :board, :rpi4)
    Application.put_env(:nerves_sign, :system_path, sys)

    case System.get_env("NERVES_SIGN_TEST_TOOLCHAIN_BIN") do
      nil -> :ok
      bin -> Application.put_env(:nerves_sign, :toolchain, bin: bin)
    end

    Application.put_env(:nerves_sign, :rpi_secure_boot,
      private_key_path: key,
      cryptinit: @cryptinit
    )

    System.put_env("NERVES_APP", app)

    on_exit(fn ->
      for {k, _} <- Application.get_all_env(:nerves_sign),
          do: Application.delete_env(:nerves_sign, k)

      for {k, v} <- prev, do: Application.put_env(:nerves_sign, k, v)

      case prev_app do
        nil -> System.delete_env("NERVES_APP")
        v -> System.put_env("NERVES_APP", v)
      end
    end)

    :ok
  end
end
