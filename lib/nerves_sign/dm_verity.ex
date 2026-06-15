defmodule NervesSign.DmVerity do
  @moduledoc """
  Generate the dm-verity hash tree for a root filesystem.

  Runs `veritysetup format` to append a hash tree to the rootfs at a
  4096-aligned offset (right after the filesystem), producing a root hash.

  This is the layout `nerves_cryptinit` expects: it derives the hash offset
  from the filesystem superblock and takes the root hash from the signed
  kernel cmdline (see `NervesSign.Cmdline`), so we only need to return the
  root hash here.

  Lifted from ex_verity.
  """
  require Logger

  @doc """
  Format `fs_path` in place, appending the hash tree. Returns
  `{root_hash, data_size}` where `data_size` is the hash offset.
  """
  @spec generate_tree!(map(), Path.t()) :: {String.t(), non_neg_integer()}
  def generate_tree!(config, fs_path) do
    block_size = Map.get(config, :block_size, 4096)
    root_hash_path = Map.get(config, :root_hash_path, Briefly.create!())

    %{size: data_size} = File.stat!(fs_path)
    Logger.info("dm-verity: formatting #{fs_path} (#{data_size} bytes, offset #{data_size})")

    case System.cmd("veritysetup", [
           "format",
           fs_path,
           fs_path,
           "--data-block-size=#{block_size}",
           "--hash-block-size=#{block_size}",
           "--hash-offset=#{data_size}",
           "--root-hash-file=#{root_hash_path}"
         ]) do
      {_, 0} ->
        root_hash = root_hash_path |> File.read!() |> String.trim()
        Logger.info("dm-verity: root hash #{root_hash}")
        {root_hash, data_size}

      {output, status} ->
        Mix.raise("veritysetup exited with #{status}:\n#{output}")
    end
  end
end
