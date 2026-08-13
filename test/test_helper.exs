# The unit tier always runs. The integration tier needs host tools and a musl
# cross-toolchain, so it opts itself in when those are already present rather
# than being hidden behind a flag people forget — a suite that runs nothing by
# default is a suite that catches nothing.
#
# Force it either way with `mix test --include integration` (what CI does, so a
# cold cache still runs the real suite) or `mix test --exclude integration`.

tools = ~w(veritysetup mksquashfs fwup mcopy cpio gzip make)
missing = Enum.reject(tools, &System.find_executable/1)

# Application env is not loaded yet at this point, so consult the env var the
# integration tests use for an out-of-tree toolchain.
toolchain =
  case System.get_env("NERVES_SIGN_TEST_TOOLCHAIN_BIN") do
    nil ->
      Application.load(:nerves_sign)
      NervesSign.Toolchain.available?(:rpi4)

    bin ->
      File.exists?(Path.join(bin, "aarch64-nerves-linux-musl-gcc"))
  end

exclude =
  cond do
    missing != [] ->
      IO.puts(:stderr, """
      note: skipping the integration tier, missing host tools: #{Enum.join(missing, ", ")}
      """)

      [:integration]

    not toolchain ->
      IO.puts(:stderr, """
      note: skipping the integration tier, no musl toolchain cached yet.
      Run `mix test --include integration` once to fetch it (or set
      NERVES_SIGN_TEST_TOOLCHAIN_BIN), and it runs by default from then on.
      """)

      [:integration]

    true ->
      []
  end

# The pipeline is chatty by design during a real firmware build; in tests the
# per-step info lines drown the failures. Warnings still surface, and
# capture_log still sees everything it asserts on.
Logger.configure(level: :warning)

ExUnit.start(exclude: exclude)
