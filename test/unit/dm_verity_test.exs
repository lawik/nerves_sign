defmodule NervesSign.DmVerityTest do
  @moduledoc """
  The hash tree is the trust anchor's other half. This checks the layout
  cryptinit depends on — tree appended at the filesystem size, root hash
  returned — and cross-checks the hash with `veritysetup verify` rather than
  trusting our own read of the file we just wrote.
  """
  use ExUnit.Case, async: true

  alias NervesSign.DmVerity

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp} do
    # Not a real filesystem: veritysetup formats whatever bytes it is given, so
    # a fixed-size blob exercises the same layout for a fraction of the time.
    fs = Path.join(tmp, "rootfs.img")
    File.write!(fs, :crypto.strong_rand_bytes(128 * 1024))
    {:ok, fs: fs, size: 128 * 1024}
  end

  if System.find_executable("veritysetup") do
    test "appends the tree at the data size and returns its root hash", c do
      {root_hash, offset} = DmVerity.generate_tree!(%{}, c.fs)

      assert root_hash =~ ~r/^[0-9a-f]{64}$/
      # cryptinit derives this offset from the filesystem superblock rather
      # than being told it, so it must land exactly at the original size.
      assert offset == c.size
      assert File.stat!(c.fs).size > c.size
    end

    test "the data below the hash tree is untouched", c do
      before = File.read!(c.fs)

      {_hash, offset} = DmVerity.generate_tree!(%{}, c.fs)

      assert binary_part(File.read!(c.fs), 0, offset) == before
    end

    test "veritysetup itself verifies the image with the returned hash", c do
      {root_hash, offset} = DmVerity.generate_tree!(%{}, c.fs)

      assert {_, 0} =
               System.cmd(
                 "veritysetup",
                 ["verify", c.fs, c.fs, root_hash, "--hash-offset=#{offset}"],
                 stderr_to_stdout: true
               )
    end

    test "a tampered image fails that same verification", c do
      {root_hash, offset} = DmVerity.generate_tree!(%{}, c.fs)

      <<head::binary-size(64), byte, tail::binary>> = File.read!(c.fs)
      File.write!(c.fs, <<head::binary, Bitwise.bxor(byte, 0xFF), tail::binary>>)

      assert {_, code} =
               System.cmd(
                 "veritysetup",
                 ["verify", c.fs, c.fs, root_hash, "--hash-offset=#{offset}"],
                 stderr_to_stdout: true
               )

      assert code != 0
    end

    test "the root hash goes where the caller asked for it", c do
      path = Path.join(c.tmp_dir, "root_hash.txt")

      {root_hash, _} = DmVerity.generate_tree!(%{root_hash_path: path}, c.fs)

      assert File.read!(path) |> String.trim() == root_hash
    end

    test "an unusable block size fails loudly instead of shipping a bad tree", c do
      err =
        assert_raise Mix.Error, ~r/veritysetup exited with/, fn ->
          DmVerity.generate_tree!(%{block_size: 999}, c.fs)
        end

      # veritysetup explains itself on stderr; without capturing it the raise
      # is just an exit code and the developer has nothing to go on.
      assert err.message =~ "block size"
    end

    test "a missing rootfs fails before veritysetup is invoked", c do
      assert_raise File.Error, fn ->
        DmVerity.generate_tree!(%{}, Path.join(c.tmp_dir, "nope.img"))
      end
    end
  end
end
