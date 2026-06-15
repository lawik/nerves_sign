defmodule NervesSign.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/lawik/nerves_sign"

  def project do
    [
      app: :nerves_sign,
      version: @version,
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "Compile-time Nerves secure boot tooling: dm-verity + dm-crypt boot.img " <>
          "generation, signing, and initramfs packaging around nerves_cryptinit",
      package: package(),
      source_url: @source_url,
      docs: [main: "readme", extras: ["README.md", "PLAN.md"]]
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      # Temp file handling for build artifacts
      {:briefly, "~> 0.5"},

      # The runtime init we package. Pinned git dep until it stabilizes on hex.
      {:nerves_cryptinit, github: "fhunleth/nerves_cryptinit", runtime: false, app: false},

      # musl cross-toolchain used to build the static initramfs binaries.
      # Nerves' artifact machinery downloads/caches/checksums it for us.
      {:nerves_toolchain_aarch64_nerves_linux_musl, "~> 14.2", runtime: false, targets: :rpi4},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url}
    ]
  end
end
