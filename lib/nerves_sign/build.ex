defmodule NervesSign.Build do
  @moduledoc """
  Helpers for building the static initramfs binaries.

  The post-processing runs inside `mix firmware`, where Nerves has exported the
  glibc target toolchain via the environment (`CC`, `CFLAGS` with
  `-D_FILE_OFFSET_BITS=64`, `CPATH` into the system sysroot, etc.). Those would
  poison the musl static build (e.g. `open64`/`pread64` undefined). We compile
  the init and helpers with a clean environment + explicit flags instead.
  """

  # Toolchain-ish env vars Nerves/ports may set that must not leak into the
  # musl static build. Cleared (unset) for our make/gcc invocations.
  @poison ~w(
    CC CXX CPP LD AR AS NM RANLIB STRIP OBJCOPY OBJDUMP
    CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
    CROSSCOMPILE CROSS_COMPILE
    CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
    PKG_CONFIG_SYSROOT_DIR PKG_CONFIG_LIBDIR PKG_CONFIG_PATH
    SYSROOT ERL_CFLAGS ERL_LDFLAGS
  )

  @doc "Environment (for System.cmd `:env`) that unsets the leaking toolchain vars."
  @spec clean_env() :: [{String.t(), nil}]
  def clean_env, do: Enum.map(@poison, &{&1, nil})
end
