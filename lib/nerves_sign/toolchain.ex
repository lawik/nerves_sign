defmodule NervesSign.Toolchain do
  @moduledoc """
  Resolve the musl cross-toolchain used to build the static initramfs binaries.

  The initramfs `init` (nerves_cryptinit) and the board key helpers are built
  static-musl so no libc needs to ship in the CPIO. This toolchain is
  independent of the glibc toolchain Nerves built the system with.

  We fetch the same artifact the `nerves_toolchain_*_musl` hex packages wrap
  (from the nerves-project/toolchains GitHub release, pinned per board) and
  cache it under `_build`. Override with:

      config :nerves_sign, toolchain: [bin: "/path/to/toolchain/bin"]
  """
  require Logger

  @releases "https://github.com/nerves-project/toolchains/releases/download"

  @doc """
  Return `%{cc: path, strip: path}` for the board's musl toolchain, fetching
  and extracting it on first use.
  """
  @spec resolve(atom()) :: %{cc: Path.t(), strip: Path.t()}
  def resolve(board) do
    case override(board) || cached(board) do
      nil -> fetch(board)
      tools -> tools
    end
  end

  @doc """
  Whether the board's toolchain can be used without going to the network: an
  explicit `:toolchain` bin override, or a copy already in the build cache.
  """
  @spec available?(atom()) :: boolean()
  def available?(board) do
    case override(board) || cached(board) do
      nil -> false
      %{cc: cc} -> File.exists?(cc)
    end
  end

  defp override(board) do
    triple = triple(board)

    case Application.get_env(:nerves_sign, :toolchain)[:bin] do
      nil -> nil
      bin -> %{cc: Path.join(bin, "#{triple}-gcc"), strip: Path.join(bin, "#{triple}-strip")}
    end
  end

  defp cached(board) do
    case find_cc(cache_dir(board), triple(board)) do
      nil -> nil
      cc -> tools(cc)
    end
  end

  defp fetch(board) do
    name = artifact_name(board)
    %{version: version} = NervesSign.Board.impl(board).toolchain()
    cache = Path.join([build_root(), "nerves_sign", "toolchains"])
    dest = cache_dir(board)

    File.mkdir_p!(cache)
    url = "#{@releases}/v#{version}/#{name}.tar.xz"
    tarball = Path.join(cache, "#{name}.tar.xz")
    Logger.info("nerves_sign: fetching musl toolchain #{name}")
    download!(url, tarball)
    File.mkdir_p!(dest)
    {_, 0} = System.cmd("tar", ["-xf", tarball, "-C", dest, "--strip-components=1"])
    File.rm(tarball)

    cc =
      find_cc(dest, triple(board)) ||
        Mix.raise("nerves_sign: gcc not found after extracting #{name}")

    tools(cc)
  end

  defp tools(cc), do: %{cc: cc, strip: String.replace_suffix(cc, "-gcc", "-strip")}

  defp triple(board), do: NervesSign.Board.impl(board).toolchain_triple()

  defp cache_dir(board),
    do: Path.join([build_root(), "nerves_sign", "toolchains", artifact_name(board)])

  @doc "Name of the toolchain release artifact this host and board need."
  @spec artifact_name(atom()) :: String.t()
  def artifact_name(board) do
    %{version: version, hash: hash} = NervesSign.Board.impl(board).toolchain()
    triple_us = String.replace(triple(board), "-", "_")
    "nerves_toolchain_#{triple_us}-#{host_tag()}-#{version}-#{hash}"
  end

  defp find_cc(dir, triple) do
    Path.wildcard(Path.join([dir, "**", "bin", "#{triple}-gcc"])) |> List.first()
  end

  defp download!(url, dest) do
    case System.cmd("curl", ["-fSL", url, "-o", dest], stderr_to_stdout: true) do
      {_, 0} -> :ok
      {out, code} -> Mix.raise("nerves_sign: toolchain download failed (#{code}):\n#{out}")
    end
  end

  defp build_root do
    if function_exported?(Mix.Project, :build_path, 0) and Mix.Project.get(),
      do: Mix.Project.build_path(),
      else: Path.join(File.cwd!(), "_build")
  end

  # Public (undocumented) for testing: this names the artifact we download,
  # and a wrong tag surfaces only as a 404 on someone else's machine.
  @doc false
  def host_tag do
    arch = :erlang.system_info(:system_architecture) |> to_string()

    cpu =
      cond do
        String.contains?(arch, "aarch64") or String.contains?(arch, "arm64") -> "aarch64"
        true -> "x86_64"
      end

    case :os.type() do
      {:unix, :darwin} -> "darwin_#{cpu}"
      {:unix, _} -> "linux_#{cpu}"
      other -> Mix.raise("nerves_sign: unsupported host #{inspect(other)}")
    end
  end
end
