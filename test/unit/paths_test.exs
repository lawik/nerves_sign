defmodule NervesSign.PathsTest do
  @moduledoc """
  Path resolution decides whether a project's edited config is used or a
  shipped default silently takes its place — a fallback that fires when it
  should not means signing something the developer never wrote.
  """
  use ExUnit.Case, async: true

  alias NervesSign.Paths

  setup do
    dir = Path.join(System.tmp_dir!(), "paths_#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(dir, "config/rpi4"))
    on_exit(fn -> File.rm_rf(dir) end)
    {:ok, app: dir}
  end

  describe "resolve/2" do
    test "relative paths hang off the app dir", %{app: app} do
      assert Paths.resolve("config/rpi4/cmdline.txt", app) ==
               Path.join(app, "config/rpi4/cmdline.txt")
    end

    test "absolute paths are left alone", %{app: app} do
      assert Paths.resolve("/etc/keys/boot.pem", app) == "/etc/keys/boot.pem"
    end

    test "a missing path fails loudly instead of later", %{app: app} do
      # Without this, a missing private_key_path surfaces as a cryptic openssl
      # error several steps further along.
      assert_raise Mix.Error, ~r/missing required path/, fn -> Paths.resolve(nil, app) end
    end
  end

  describe "project_config/2" do
    test "names the directory the gen task writes into" do
      assert Paths.project_config(:rpi4, "cmdline.txt") == "config/rpi4/cmdline.txt"
    end

    test "cm4 shares rpi4's generated config, since one gen task serves both" do
      assert Paths.project_config(:cm4, "config.txt") == Paths.project_config(:rpi4, "config.txt")
    end

    test "keeps a nested layout intact" do
      assert Paths.project_config(:rpi4, "fwup_include/fwup-common.conf") ==
               "config/rpi4/fwup_include/fwup-common.conf"
    end

    test "an unsupported board is refused rather than guessed at" do
      assert_raise Mix.Error, ~r/unsupported board/, fn ->
        Paths.project_config(:imx8, "config.txt")
      end
    end
  end

  describe "board_file/2" do
    test "points into the board's priv dir" do
      path = Paths.board_file(:rpi4, "boot_fwup.conf")

      assert String.ends_with?(path, "boards/rpi4/boot_fwup.conf")
      assert File.exists?(path)
    end

    test "cm4 shares the rpi4 assets" do
      assert Paths.board_file(:cm4, "config.txt") == Paths.board_file(:rpi4, "config.txt")
    end
  end

  describe "project_file!/4" do
    test "uses the project's file when it is there", %{app: app} do
      path = Path.join(app, "config/rpi4/boot_fwup.conf")
      File.write!(path, "# mine\n")

      assert Paths.project_file!(nil, app, "config/rpi4/boot_fwup.conf", "gen.rpi4") == path
    end

    test "refuses to fall back to the library's copy", %{app: app} do
      # Signing our device tree list and our overlays under the project's key,
      # because they forgot to generate the file, is the worst outcome here.
      err =
        assert_raise Mix.Error, fn ->
          Paths.project_file!(nil, app, "config/rpi4/boot_fwup.conf", "nerves_sign.gen.rpi4")
        end

      assert err.message =~ "not found"
      assert err.message =~ "will not substitute its own copy"
      assert err.message =~ "mix nerves_sign.gen.rpi4"
    end

    test "an explicit setting is honoured when it exists", %{app: app} do
      File.mkdir_p!(Path.join(app, "custom"))
      path = Path.join(app, "custom/boot.conf")
      File.write!(path, "# elsewhere\n")

      assert Paths.project_file!("custom/boot.conf", app, "config/rpi4/x.conf", "gen") == path
    end

    test "an explicit setting that is missing still raises", %{app: app} do
      err =
        assert_raise Mix.Error, fn ->
          Paths.project_file!("custom/gone.conf", app, "config/rpi4/x.conf", "gen")
        end

      # Names the path they actually asked for, not the default.
      assert err.message =~ "custom/gone.conf"
    end

    test "absolute settings work too", %{app: app} do
      path = Path.join(app, "abs.conf")
      File.write!(path, "x")

      assert Paths.project_file!(path, app, "config/rpi4/x.conf", "gen") == path
    end
  end

  describe "project_or_board/5" do
    test "falls back to the shipped board file when the project has none", %{app: app} do
      resolved =
        Paths.project_or_board(:rpi4, nil, app, "config/rpi4/boot_fwup.conf", "boot_fwup.conf")

      assert resolved == Paths.board_file(:rpi4, "boot_fwup.conf")
    end

    test "the project's generated copy wins over the shipped one", %{app: app} do
      project = Path.join(app, "config/rpi4/boot_fwup.conf")
      File.write!(project, "# edited by the developer\n")

      assert Paths.project_or_board(
               :rpi4,
               nil,
               app,
               "config/rpi4/boot_fwup.conf",
               "boot_fwup.conf"
             ) ==
               project
    end

    test "an explicit config setting beats both", %{app: app} do
      File.write!(Path.join(app, "config/rpi4/boot_fwup.conf"), "# generated\n")

      assert Paths.project_or_board(
               :rpi4,
               "custom/boot_fwup.conf",
               app,
               "config/rpi4/boot_fwup.conf",
               "boot_fwup.conf"
             ) == Path.join(app, "custom/boot_fwup.conf")
    end

    test "an explicit absolute setting is used verbatim", %{app: app} do
      assert Paths.project_or_board(
               :rpi4,
               "/srv/boot_fwup.conf",
               app,
               "config/rpi4/boot_fwup.conf",
               "boot_fwup.conf"
             ) == "/srv/boot_fwup.conf"
    end

    test "an explicit setting is not quietly replaced when the file is absent", %{app: app} do
      # Silently signing the board default instead of the file the developer
      # asked for is the worst possible outcome here.
      resolved =
        Paths.project_or_board(
          :rpi4,
          "custom/missing.conf",
          app,
          "config/rpi4/x.conf",
          "boot_fwup.conf"
        )

      assert resolved == Path.join(app, "custom/missing.conf")
      refute resolved == Paths.board_file(:rpi4, "boot_fwup.conf")
    end
  end
end
