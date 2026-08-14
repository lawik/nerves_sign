defmodule NervesSign.Boards.RPi.HelpersTest do
  @moduledoc """
  Runs the C helpers' own host tests, so they are part of this suite rather
  than something you have to remember to run.

  The OTP rows these touch are one-time programmable: a bit burned to 1 never
  goes back. That makes the refusal logic the most important code in the
  helper and the least testable on real hardware, which is why it sits behind
  a mailbox seam with an in-memory fake.
  """
  use ExUnit.Case, async: true

  @helpers Path.join([:code.priv_dir(:nerves_sign), "boards/rpi/helpers"])

  if is_nil(System.find_executable("cc")) do
    @moduletag skip: "no host C compiler"
  end

  test "the C helpers pass their host tests" do
    {out, code} = System.cmd("make", ["-C", @helpers, "test"], stderr_to_stdout: true)

    assert code == 0, out
    assert out =~ "otp: all checks passed"

    # The conversion state machine: power loss between stages, resuming a
    # half-written rootfs, refusing a device it does not recognise. None of
    # those are reachable through bodge, QEMU, or a Pi.
    assert out =~ "bootstrap: all checks passed"
  end

  test "the helper sources it builds from are the ones we ship" do
    sources =
      ~w(unlock.c otp.c otp.h mailbox.c mailbox.h Makefile
         bootstrap.c bootstrap.h blockdev.c blockdev.h crypt.h)

    for name <- sources do
      assert File.exists?(Path.join(@helpers, name)), "#{name} is missing from priv"
    end
  end

  test "nothing in the helper shells out" do
    # cryptinit's boundary: syscalls, not subprocesses. A helper that runs
    # /bin/sh in an initramfs that has no shell fails at the worst moment.
    for name <- ~w(unlock.c otp.c mailbox.c bootstrap.c blockdev.c) do
      source = @helpers |> Path.join(name) |> File.read!()

      # Word boundaries: `bootstrap_is_filesystem(` is not a call to system().
      for banned <- [
            ~r/\bsystem\(/,
            ~r/\bpopen\(/,
            ~r/\bexecl/,
            ~r/\bexecvp/,
            ~r/\bfork\(/,
            ~r|/bin/sh|
          ] do
        refute source =~ banned, "#{name} matches #{inspect(banned)}"
      end
    end
  end
end
