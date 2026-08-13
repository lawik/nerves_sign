defmodule NervesSign.Boards.RPiTest do
  @moduledoc """
  The secure boot settings — signing key, config.txt and cmdline.txt paths —
  were never specific to the Pi 4, so the config key that carries them is not
  either. The old name still works, loudly.
  """
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias NervesSign.Boards.RPi

  setup do
    prev = Application.get_all_env(:nerves_sign)

    on_exit(fn ->
      for {k, _} <- Application.get_all_env(:nerves_sign),
          do: Application.delete_env(:nerves_sign, k)

      for {k, v} <- prev, do: Application.put_env(:nerves_sign, k, v)
    end)

    Application.delete_env(:nerves_sign, :rpi_secure_boot)
    Application.delete_env(:nerves_sign, :rpi4_secure_boot)
    :ok
  end

  test "reads the current key as a map, without complaint" do
    Application.put_env(:nerves_sign, :rpi_secure_boot, private_key_path: "/keys/boot.pem")

    log =
      capture_log(fn ->
        assert RPi.secure_boot_config() == %{private_key_path: "/keys/boot.pem"}
      end)

    assert log == ""
  end

  test "an unset block is empty rather than nil" do
    # PostProcess indexes into this for optional settings, so nil would crash
    # instead of falling back to defaults.
    assert capture_log(fn -> assert RPi.secure_boot_config() == %{} end) == ""
  end

  test "the deprecated key still works, and says what to rename it to" do
    Application.put_env(:nerves_sign, :rpi4_secure_boot, private_key_path: "/keys/old.pem")

    log =
      capture_log(fn ->
        assert RPi.secure_boot_config() == %{private_key_path: "/keys/old.pem"}
      end)

    assert log =~ "rpi4_secure_boot"
    assert log =~ "rpi_secure_boot"
    assert log =~ "deprecated"
  end

  test "the current key wins when both are set, and says so" do
    Application.put_env(:nerves_sign, :rpi_secure_boot, private_key_path: "/keys/new.pem")
    Application.put_env(:nerves_sign, :rpi4_secure_boot, private_key_path: "/keys/old.pem")

    log =
      capture_log(fn ->
        assert RPi.secure_boot_config() == %{private_key_path: "/keys/new.pem"}
      end)

    assert log =~ "ignoring"
  end

  test "the gen task tells people the current name" do
    # A generator that prints a deprecated key would keep it alive forever.
    source = File.read!("lib/mix/tasks/nerves_sign.gen.rpi4.ex")

    assert source =~ "rpi_secure_boot:"
    refute source =~ "rpi4_secure_boot:"
  end
end
