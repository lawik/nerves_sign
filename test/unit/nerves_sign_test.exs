defmodule NervesSignTest do
  use ExUnit.Case, async: false

  setup do
    prev = Application.get_env(:nerves_sign, :board)

    on_exit(fn ->
      if prev,
        do: Application.put_env(:nerves_sign, :board, prev),
        else: Application.delete_env(:nerves_sign, :board)
    end)

    :ok
  end

  test "board/0 returns the configured board" do
    Application.put_env(:nerves_sign, :board, :cm4)

    assert NervesSign.board() == :cm4
  end

  test "an unconfigured board says exactly what to add and where" do
    Application.delete_env(:nerves_sign, :board)

    err = assert_raise Mix.Error, fn -> NervesSign.board() end

    assert err.message =~ "config :nerves_sign, board: :rpi4"
    assert err.message =~ "target config"
  end
end
