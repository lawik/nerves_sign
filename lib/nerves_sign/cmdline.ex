defmodule NervesSign.Cmdline do
  @moduledoc """
  Inject the dm-verity root hash into the kernel cmdline.

  `nerves_cryptinit` reads `verity_roothash=` from the (signed) kernel cmdline
  as its trust anchor. We compute the hash at build time
  (`NervesSign.DmVerity`) and write it into the inner `cmdline.txt`.

  The whole `cmdline.txt` is passed to the kernel as parameters, so the output
  is a single clean line: comment (`#`) and blank lines are dropped, any
  existing `verity_roothash=` is replaced, and the new value is appended.
  """

  @doc "Return a single-line cmdline from `template_path` with `verity_roothash=<hash>` set."
  @spec with_roothash(Path.t(), String.t()) :: String.t()
  def with_roothash(template_path, root_hash) do
    params =
      template_path
      |> File.read!()
      |> String.split("\n")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))
      |> Enum.join(" ")
      |> String.split()
      |> Enum.reject(&String.starts_with?(&1, "verity_roothash="))

    Enum.join(params ++ ["verity_roothash=#{root_hash}"], " ") <> "\n"
  end
end
