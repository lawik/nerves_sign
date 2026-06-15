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
    triple = NervesSign.Board.impl(board).toolchain_triple()

    case Application.get_env(:nerves_sign, :toolchain)[:bin] do
      nil -> fetch(board, triple)
      bin -> %{cc: Path.join(bin, "#{triple}-gcc"), strip: Path.join(bin, "#{triple}-strip")}
    end
  end

  defp fetch(board, triple) do
    %{version: version, hash: hash} = NervesSign.Board.impl(board).toolchain()
    host = host_tag()
    triple_us = String.replace(triple, "-", "_")
    name = "nerves_toolchain_#{triple_us}-#{host}-#{version}-#{hash}"
    cache = Path.join([build_root(), "nerves_sign", "toolchains"])
    dest = Path.join(cache, name)
    cc = find_cc(dest, triple)

    if cc do
      %{cc: cc, strip: String.replace_suffix(cc, "-gcc", "-strip")}
    else
      File.mkdir_p!(cache)
      url = "#{@releases}/v#{version}/#{name}.tar.xz"
      tarball = Path.join(cache, "#{name}.tar.xz")
      Logger.info("nerves_sign: fetching musl toolchain #{name}")
      download!(url, tarball)
      File.mkdir_p!(dest)
      {_, 0} = System.cmd("tar", ["-xf", tarball, "-C", dest, "--strip-components=1"])
      File.rm(tarball)

      cc =
        find_cc(dest, triple) || Mix.raise("nerves_sign: gcc not found after extracting #{name}")

      %{cc: cc, strip: String.replace_suffix(cc, "-gcc", "-strip")}
    end
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

  defp host_tag do
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
