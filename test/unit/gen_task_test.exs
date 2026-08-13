defmodule Mix.Tasks.NervesSign.Gen.Rpi4Test do
  @moduledoc """
  The gen task is how every project gets its config. A file listed but missing
  from priv, or a re-run that overwrites edits, breaks people quietly.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  @task Mix.Tasks.NervesSign.Gen.Rpi4

  @generated ~w(
    config/rpi4/fwup.conf
    config/rpi4/fwup_include/fwup-common.conf
    config/rpi4/boot_fwup.conf
    config/rpi4/config.txt
    config/rpi4/cmdline.txt
    config/rpi4/initramfs.conf
    priv/nerves_sign/post_process
  )

  setup do
    dir = Path.join(System.tmp_dir!(), "gen_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    cwd = File.cwd!()
    File.cd!(dir)

    Mix.shell(Mix.Shell.Process)

    on_exit(fn ->
      File.cd!(cwd)
      File.rm_rf(dir)
      Mix.shell(Mix.Shell.IO)
    end)

    {:ok, dir: dir}
  end

  defp run, do: @task.run([])

  # Mix.Shell.Process posts each line to the test process mailbox.
  defp output(acc \\ []) do
    receive do
      {:mix_shell, :info, [msg]} -> output([msg | acc])
    after
      0 -> acc |> Enum.reverse() |> Enum.join("\n")
    end
  end

  test "generates every file it advertises" do
    run()
    out = output()

    for path <- @generated do
      assert File.exists?(path), "#{path} was not generated"
      assert out =~ "created #{path}"
    end
  end

  test "the generated config is the config the pipeline validates against" do
    run()

    # A generated project must pass preflight out of the box; if the shipped
    # config.txt and cmdline.txt do not agree with the shipped boot_fwup.conf,
    # every new project starts broken.
    rendered =
      NervesSign.Cmdline.with_roothash("config/rpi4/cmdline.txt", String.duplicate("a", 64))

    log =
      capture_log(fn ->
        assert NervesSign.Preflight.check!(:rpi4, %{
                 board: :rpi4,
                 cmdline: rendered,
                 config_txt: "config/rpi4/config.txt",
                 boot_fwup_conf: "config/rpi4/boot_fwup.conf"
               }) == :ok
      end)

    # Not even a warning: a freshly generated project should be clean.
    assert log == ""
  end

  test "generates into the directory the board declares" do
    run()

    # The gen task and post-processing must agree on where these live; both go
    # through the board rather than repeating the path.
    for name <- ~w(config.txt cmdline.txt boot_fwup.conf initramfs.conf) do
      assert File.exists?(NervesSign.Paths.project_config(:rpi4, name))
    end
  end

  test "the outer fwup.conf includes the common file at the path it generates" do
    run()

    assert File.read!("config/rpi4/fwup.conf") =~
             "${NERVES_APP}/config/rpi4/fwup_include/fwup-common.conf"

    assert File.exists?("config/rpi4/fwup_include/fwup-common.conf")
  end

  test "the post_process bridge is executable, or mix firmware cannot run it" do
    run()

    assert %{mode: mode} = File.stat!("priv/nerves_sign/post_process")
    assert Bitwise.band(mode, 0o111) != 0
  end

  test "the bridge calls into the library entrypoint" do
    run()

    assert File.read!("priv/nerves_sign/post_process") =~ "NervesSign.run"
  end

  test "re-running does not overwrite developer edits" do
    run()
    Mix.Shell.Process.flush()

    File.write!("config/rpi4/config.txt", "# my edits\n")
    run()

    assert File.read!("config/rpi4/config.txt") == "# my edits\n"
    assert output() =~ "skipping config/rpi4/config.txt (exists)"
  end

  test "prints the kernel config the board cannot boot without" do
    run()
    out = output()

    for symbol <- NervesSign.Boards.RPi4.required_kernel_config() do
      assert out =~ symbol
    end
  end

  test "prints wiring for both the firmware hook and the board" do
    run()
    out = output()

    assert out =~ "post_processing_script"
    assert out =~ "board: :rpi4"
    assert out =~ "fwup_conf: \"config/rpi4/fwup.conf\""
  end
end
