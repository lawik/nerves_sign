defmodule NervesSign.BuildTest do
  @moduledoc """
  The poison list is the fix for a real class of breakage: Nerves exports the
  glibc target toolchain into the environment during `mix firmware`, and those
  variables leaking into the musl static build produce undefined `open64` /
  `pread64` at link time. Nothing else pins the list, so this does.
  """
  use ExUnit.Case, async: true

  alias NervesSign.Build

  test "clean_env unsets rather than blanks" do
    # System.cmd treats nil as "remove from the environment"; "" would still be
    # set, and an empty CC is worse than an absent one.
    for {name, value} <- Build.clean_env() do
      assert is_binary(name)
      assert value == nil
    end
  end

  test "clears the compiler and flag variables Nerves exports" do
    cleared = Build.clean_env() |> Enum.map(&elem(&1, 0)) |> MapSet.new()

    for name <- ~w(CC CFLAGS LDFLAGS CROSSCOMPILE CPATH ERL_CFLAGS) do
      assert name in cleared, "#{name} would leak into the musl static build"
    end
  end

  test "clears the pkg-config sysroot vars that point into the glibc system" do
    cleared = Build.clean_env() |> Enum.map(&elem(&1, 0)) |> MapSet.new()

    for name <- ~w(PKG_CONFIG_SYSROOT_DIR PKG_CONFIG_LIBDIR PKG_CONFIG_PATH SYSROOT) do
      assert name in cleared
    end
  end

  test "leaves PATH alone, or make and gcc could not be found at all" do
    cleared = Build.clean_env() |> Enum.map(&elem(&1, 0)) |> MapSet.new()

    refute "PATH" in cleared
    refute "HOME" in cleared
  end

  test "actually strips the variable from a child process" do
    System.put_env("CFLAGS", "-D_FILE_OFFSET_BITS=64")
    on_exit(fn -> System.delete_env("CFLAGS") end)

    {out, 0} = System.cmd("sh", ["-c", "echo \"[${CFLAGS-unset}]\""], env: Build.clean_env())

    assert String.trim(out) == "[unset]"
  end
end
