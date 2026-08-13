defmodule NervesSign.ToolchainTest do
  @moduledoc """
  The fetch path needs the network, so what is covered here is everything that
  decides *which* artifact gets fetched and *what* gets executed — the parts
  that fail as a 404 or a wrong compiler on someone else's machine.
  """
  use ExUnit.Case, async: false

  alias NervesSign.Toolchain

  setup do
    prev = Application.get_env(:nerves_sign, :toolchain)
    tmp = Path.join(System.tmp_dir!(), "tc_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)

    on_exit(fn ->
      if prev,
        do: Application.put_env(:nerves_sign, :toolchain, prev),
        else: Application.delete_env(:nerves_sign, :toolchain)

      File.rm_rf(tmp)
    end)

    {:ok, tmp: tmp}
  end

  describe "resolve/1 with an explicit bin dir" do
    test "derives cc and strip from the board triple, without touching the network" do
      Application.put_env(:nerves_sign, :toolchain, bin: "/opt/tc/bin")

      assert Toolchain.resolve(:rpi4) == %{
               cc: "/opt/tc/bin/aarch64-nerves-linux-musl-gcc",
               strip: "/opt/tc/bin/aarch64-nerves-linux-musl-strip"
             }
    end

    test "cm4 resolves through the same board module as rpi4" do
      Application.put_env(:nerves_sign, :toolchain, bin: "/opt/tc/bin")

      assert Toolchain.resolve(:cm4) == Toolchain.resolve(:rpi4)
    end

    test "it is a musl toolchain, not the glibc one Nerves builds the system with" do
      Application.put_env(:nerves_sign, :toolchain, bin: "/opt/tc/bin")

      assert Toolchain.resolve(:rpi4).cc =~ "musl"
    end
  end

  describe "host_tag/0" do
    test "names a host the toolchain release actually publishes" do
      assert Toolchain.host_tag() in ~w(linux_x86_64 linux_aarch64 darwin_x86_64 darwin_aarch64)
    end

    test "matches the machine the tests are running on" do
      expected = if match?({:unix, :darwin}, :os.type()), do: "darwin", else: "linux"

      assert String.starts_with?(Toolchain.host_tag(), expected)
    end
  end

  describe "available?/1" do
    test "false for a bin override that has no compiler in it" do
      Application.put_env(:nerves_sign, :toolchain, bin: "/nonexistent/bin")

      refute Toolchain.available?(:rpi4)
    end

    test "true for a bin override that does", %{tmp: tmp} do
      File.write!(Path.join(tmp, "aarch64-nerves-linux-musl-gcc"), "")
      Application.put_env(:nerves_sign, :toolchain, bin: tmp)

      assert Toolchain.available?(:rpi4)
    end

    test "never goes to the network to answer" do
      Application.delete_env(:nerves_sign, :toolchain)

      # Whatever the answer, it must come back immediately from the filesystem.
      assert is_boolean(Toolchain.available?(:rpi4))
    end
  end

  describe "the pinned artifact" do
    test "the rpi4 pin has the shape the release URL is built from" do
      %{version: version, hash: hash} = NervesSign.Boards.RPi4.toolchain()

      assert version =~ ~r/^\d+\.\d+\.\d+$/
      assert hash =~ ~r/^[0-9A-F]+$/
    end

    test "the artifact name matches the nerves_toolchain_*_musl hex package naming" do
      %{version: version, hash: hash} = NervesSign.Boards.RPi4.toolchain()

      assert Toolchain.artifact_name(:rpi4) ==
               "nerves_toolchain_aarch64_nerves_linux_musl-#{Toolchain.host_tag()}-#{version}-#{hash}"
    end
  end
end
