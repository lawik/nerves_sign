defmodule NervesSign.PreflightTest do
  @moduledoc """
  The board-agnostic half: the contract `nerves_cryptinit` imposes on the
  kernel cmdline. These hold for any board that boots the init we package, so
  they stay here rather than moving into a board.

  The Raspberry Pi boot firmware contract lives in
  `NervesSign.Boards.RPi.PreflightTest`.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias NervesSign.Preflight

  @good "console=ttyS0,115200 root=/dev/mmcblk0p2 rootfstype=squashfs ro rootwait\n"

  describe "check_cmdline!/1" do
    test "accepts a cmdline that satisfies cryptinit" do
      assert capture_log(fn -> assert Preflight.check_cmdline!(@good) == :ok end) == ""
    end

    test "rejects a cmdline with no root=" do
      assert_raise Mix.Error, ~r/has no `root=`/, fn ->
        Preflight.check_cmdline!("console=ttyS0 rootfstype=squashfs ro\n")
      end
    end

    test "rejects root= pointing at the dm device cryptinit itself creates" do
      err =
        assert_raise Mix.Error, fn ->
          Preflight.check_cmdline!("console=ttyS0 root=/dev/dm-0 rootfstype=squashfs ro\n")
        end

      assert err.message =~ "device-mapper node"
      assert err.message =~ "cryptinit's output, not its input"
    end

    test "rejects root=/dev/mapper/ too" do
      assert_raise Mix.Error, ~r/device-mapper node/, fn ->
        Preflight.check_cmdline!("root=/dev/mapper/vroot ro\n")
      end
    end

    test "does not confuse rootfstype=, rootwait or rootflags= for root=" do
      assert_raise Mix.Error, ~r/has no `root=`/, fn ->
        Preflight.check_cmdline!("rootfstype=squashfs rootwait rootflags=x ro\n")
      end
    end

    test "warns when ro is missing, since the verity device is read-only" do
      log =
        capture_log(fn ->
          assert Preflight.check_cmdline!("root=/dev/mmcblk0p2 rootfstype=squashfs\n") == :ok
        end)

      assert log =~ "read-only"
    end

    test "does not mistake a substring for the ro flag" do
      log =
        capture_log(fn ->
          assert Preflight.check_cmdline!("root=/dev/mmcblk0p2 rootwait quiet\n") == :ok
        end)

      assert log =~ "read-only"
    end

    test "the rendered cmdline from the shipped rpi4 template passes" do
      template = Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4", "cmdline.txt"])
      rendered = NervesSign.Cmdline.with_roothash(template, String.duplicate("a", 64))

      assert capture_log(fn -> assert Preflight.check_cmdline!(rendered) == :ok end) == ""
    end
  end

  describe "check!/2" do
    setup do
      dir = Path.join(System.tmp_dir!(), "pre_#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf(dir) end)

      config_txt = Path.join(dir, "config.txt")

      File.write!(config_txt, """
      arm_64bit=1
      boot_ramdisk=1
      kernel=Image
      initramfs rootfs.cpio.gz
      cmdline=cmdline.txt
      """)

      fwup = Path.join([:code.priv_dir(:nerves_sign), "boards/rpi4", "boot_fwup.conf"])

      {:ok, ctx: %{board: :rpi4, cmdline: @good, config_txt: config_txt, boot_fwup_conf: fwup}}
    end

    test "hands the board the context it needs", %{ctx: ctx} do
      assert capture_log(fn -> assert Preflight.check!(:rpi4, ctx) == :ok end) == ""
    end

    test "cm4 dispatches to the same board module", %{ctx: ctx} do
      assert capture_log(fn -> assert Preflight.check!(:cm4, ctx) == :ok end) == ""
    end

    test "the board half still runs when the cmdline is fine", %{ctx: ctx} do
      File.write!(ctx.config_txt, "arm_64bit=1\nkernel=Image\n")

      assert_raise Mix.Error, ~r/has no `initramfs` directive/, fn ->
        Preflight.check!(:rpi4, ctx)
      end
    end

    test "the cryptinit contract gates the board, not the other way round", %{ctx: ctx} do
      # Point at a file that cannot be read: if the board half ran first this
      # would be a File.Error. A board must never be reached with a cmdline
      # cryptinit would reject.
      ctx = %{ctx | cmdline: "quiet\n", config_txt: "/nonexistent/config.txt"}

      assert_raise Mix.Error, ~r/has no `root=`/, fn -> Preflight.check!(:rpi4, ctx) end
    end

    test "an unsupported board is refused rather than skipped", %{ctx: ctx} do
      # Silently signing for a board with no validation would be the worst
      # possible reading of "board not supported".
      assert_raise Mix.Error, ~r/unsupported board/, fn -> Preflight.check!(:imx8, ctx) end
    end
  end

  describe "the Board behaviour" do
    # A board that boots nothing like a Pi: no FAT, no config.txt, its own
    # contract entirely. If this compiles and satisfies the behaviour, nothing
    # RPi-specific has leaked into the shared half.
    defmodule TrustZoneBoard do
      @moduledoc false
      @behaviour NervesSign.Board

      @impl true
      def toolchain_triple, do: "aarch64-nerves-linux-musl"
      @impl true
      def toolchain, do: %{version: "14.2.0", hash: "4D401D0"}
      @impl true
      def required_kernel_config, do: ~w(CONFIG_DM_VERITY)
      @impl true
      def priv_dir, do: "boards/imaginary"

      @impl true
      def config_dir, do: "imaginary"
      @impl true
      def default_key_helper_source, do: "boards/imaginary/helpers/unlock.c"

      @impl true
      def preflight!(ctx) do
        # No config.txt to read, no FAT to list: this board would check its own
        # signed container instead, from the same ctx.
        send(self(), {:preflight, Map.keys(ctx)})
        :ok
      end
    end

    test "preflight! is required, so a new board must state its contract" do
      assert {:preflight!, 1} in NervesSign.Board.behaviour_info(:callbacks)
    end

    test "a board with no config.txt and no FAT can satisfy the behaviour" do
      for {fun, arity} <- NervesSign.Board.behaviour_info(:callbacks) do
        assert function_exported?(TrustZoneBoard, fun, arity),
               "TrustZoneBoard is missing #{fun}/#{arity}"
      end

      assert TrustZoneBoard.preflight!(%{board: :imaginary, cmdline: @good}) == :ok
      assert_received {:preflight, _keys}
    end

    test "the shared half needs nothing from the board's context" do
      # check_cmdline!/1 takes a string, so it cannot grow a board dependency
      # by accident.
      assert capture_log(fn -> assert Preflight.check_cmdline!(@good) == :ok end) == ""
    end
  end
end
