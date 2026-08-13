defmodule NervesSign.Fwup do
  @moduledoc """
  Read facts back out of an fwup config.

  Not board-specific: any board whose boot image is a FAT filesystem built by
  fwup describes its contents the same way. A board whose ROM loads something
  else entirely — a signed container at a raw offset, a FIT image — simply has
  no use for this.
  """

  @fat_write ~r/fat_write\(\s*\$\{[A-Za-z_][A-Za-z0-9_]*\}\s*,\s*"([^"]+)"\s*\)/

  @doc """
  The set of filenames a fwup config writes into a FAT image, taken from its
  `fat_write` targets. Subdirectories are kept as written, e.g.
  `"overlays/vc4-kms-v3d.dtbo"`.
  """
  @spec fat_files(Path.t()) :: MapSet.t(String.t())
  def fat_files(conf) do
    @fat_write
    |> Regex.scan(File.read!(conf), capture: :all_but_first)
    |> Enum.map(&hd/1)
    |> MapSet.new()
  end
end
