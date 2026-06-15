defmodule NervesSign.Cryptinit do
  @moduledoc """
  Build the nerves_cryptinit `init` binary from source (static, musl).

  We build from source rather than trusting a prebuilt — and because the init
  has to live inside the signed boot.img anyway.
  """
  require Logger

  @doc """
  Build cryptinit's `init` with the given toolchain `%{cc, strip}` and return
  the path to the stripped static binary.
  """
  @spec build(%{cc: Path.t(), strip: Path.t()}) :: Path.t()
  def build(%{cc: cc, strip: strip}) do
    src = source_dir()
    Logger.info("nerves_sign: building cryptinit init (#{src})")

    {_, 0} = System.cmd("make", ["-C", src, "clean"], stderr_to_stdout: true)

    case System.cmd("make", ["-C", src, "CC=#{cc}", "LDFLAGS=-static"], stderr_to_stdout: true) do
      {_, 0} ->
        init = Path.join(src, "init")
        {_, 0} = System.cmd(strip, [init])
        init

      {out, code} ->
        Mix.raise("nerves_sign: cryptinit build failed (#{code}):\n#{out}")
    end
  end

  defp source_dir do
    base = Path.join(Mix.Project.deps_path(), "nerves_cryptinit/src")

    if File.dir?(base),
      do: base,
      else: Mix.raise("nerves_sign: nerves_cryptinit source not found at #{base}")
  end
end
