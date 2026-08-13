defmodule NervesSign.BoardTest do
  use ExUnit.Case, async: false

  alias NervesSign.Board
  alias NervesSign.Boards.RPi4

  setup do
    prev = Application.get_all_env(:nerves_sign)

    on_exit(fn ->
      for {k, _} <- Application.get_all_env(:nerves_sign),
          do: Application.delete_env(:nerves_sign, k)

      for {k, v} <- prev, do: Application.put_env(:nerves_sign, k, v)
    end)

    :ok
  end

  describe "impl/1" do
    test "rpi4 and cm4 share the same board module" do
      assert Board.impl(:rpi4) == RPi4
      assert Board.impl(:cm4) == RPi4
    end

    test "an unsupported board names itself in the error" do
      assert_raise Mix.Error, ~r/unsupported board :beaglebone/, fn -> Board.impl(:beaglebone) end
    end
  end

  describe "cipher/2" do
    test "defaults to the board cipher for both volumes" do
      assert Board.cipher(:rpi4, :rootfs) == "aes-xts-plain64"
      assert Board.cipher(:rpi4, :data) == "aes-xts-plain64"
    end

    test "a project override wins per volume" do
      Application.put_env(:nerves_sign, :rootfs_cipher, "aes-cbc-plain")

      assert Board.cipher(:rpi4, :rootfs) == "aes-cbc-plain"
      # Overriding one volume must not silently change the other.
      assert Board.cipher(:rpi4, :data) == "aes-xts-plain64"
    end

    test "rejects a volume that is neither rootfs nor data" do
      assert_raise FunctionClauseError, fn -> Board.cipher(:rpi4, :app) end
    end
  end

  describe "key_helper_source/1" do
    test "defaults to the helper shipped in priv, and it exists" do
      src = Board.key_helper_source(:rpi4)

      # boards/rpi, not boards/rpi4: the VideoCore mailbox the helper reads is
      # a family interface, so every Pi shares one copy.
      assert String.ends_with?(src, "boards/rpi/helpers/unlock.c")
      assert File.exists?(src)
    end

    test "rpi4 and cm4 resolve to the same shared helper" do
      assert Board.key_helper_source(:rpi4) == Board.key_helper_source(:cm4)
    end

    test "the shared helper builds with the Makefile next to it" do
      dir = Path.dirname(Board.key_helper_source(:rpi4))

      # Initramfs.build_helper drives this Makefile when the source is the
      # default unlock.c; without it the build silently takes the other branch.
      assert File.exists?(Path.join(dir, "Makefile"))
    end

    test "an absolute override is used as-is" do
      Application.put_env(:nerves_sign, :key_helper_source, "/opt/keys/hkdf.c")

      assert Board.key_helper_source(:rpi4) == "/opt/keys/hkdf.c"
    end

    test "a relative override resolves against the project" do
      Application.put_env(:nerves_sign, :key_helper_source, "priv/secure_boot/unlock.c")

      assert Board.key_helper_source(:rpi4) ==
               Path.join(File.cwd!(), "priv/secure_boot/unlock.c")
    end
  end

  describe "the rpi4 board" do
    test "implements the behaviour completely" do
      callbacks = NervesSign.Board.behaviour_info(:callbacks)

      for {fun, arity} <- callbacks do
        assert function_exported?(RPi4, fun, arity),
               "RPi4 is missing #{fun}/#{arity} required by NervesSign.Board"
      end
    end

    test "declares the kernel config cryptinit cannot work without" do
      required = RPi4.required_kernel_config()

      # No module loading happens in the initramfs, so these must be =y.
      for symbol <- ~w(CONFIG_BLK_DEV_INITRD CONFIG_DM_VERITY CONFIG_CRYPTO_SHA256) do
        assert symbol in required
      end
    end

    test "the default cipher matches the crypto it requires in the kernel" do
      assert RPi4.default_cipher() == "aes-xts-plain64"
      assert "CONFIG_CRYPTO_XTS" in RPi4.required_kernel_config()
    end

    test "config_dir is where the gen task writes and post-processing reads" do
      # Declared, not derived from priv_dir: these paths exist on developers'
      # disks, so an internal rename must not move them.
      assert NervesSign.Boards.RPi4.config_dir() == "rpi4"
    end

    test "priv_dir points at a directory that ships" do
      assert File.dir?(Path.join(:code.priv_dir(:nerves_sign), RPi4.priv_dir()))
    end
  end
end
