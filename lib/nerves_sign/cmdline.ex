defmodule NervesSign.Cmdline do
  @moduledoc """
  Inject the dm-verity root hash into the inner kernel cmdline.

  `nerves_cryptinit` reads `verity_roothash=` from the (signed) kernel cmdline
  as its trust anchor. We compute the hash at build time (`NervesSign.DmVerity`)
  and write it into the inner `cmdline.txt` that goes inside `boot.img`.
  """

  @doc """
  Return the contents of `template_path` with `verity_roothash=<hash>` set
  (replacing any existing value), suitable to write as the inner cmdline.txt.
  """
  @spec with_roothash(Path.t(), String.t()) :: String.t()
  def with_roothash(template_path, root_hash) do
    template_path
    |> File.read!()
    |> String.split("\n")
    |> Enum.map(&strip_existing/1)
    |> Enum.join("\n")
    |> append_param("verity_roothash=#{root_hash}")
  end

  defp strip_existing(line) do
    if String.starts_with?(String.trim_leading(line), "#") do
      line
    else
      line
      |> String.split()
      |> Enum.reject(&String.starts_with?(&1, "verity_roothash="))
      |> Enum.join(" ")
    end
  end

  # Append to the first non-comment, non-empty parameter line.
  defp append_param(text, param) do
    {lines, done} =
      text
      |> String.split("\n")
      |> Enum.map_reduce(false, fn line, done ->
        trimmed = String.trim(line)

        if not done and trimmed != "" and not String.starts_with?(trimmed, "#") do
          {String.trim_trailing(line) <> " " <> param, true}
        else
          {line, done}
        end
      end)

    if done, do: Enum.join(lines, "\n"), else: text <> "\n" <> param <> "\n"
  end
end
