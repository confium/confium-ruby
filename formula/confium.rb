# Homebrew formula for the Confium CLI.
#
# Install via custom tap:
#   brew tap confium/tap https://github.com/confium/homebrew-tap
#   brew install confium
#
# Or one-shot:
#   brew install confium/tap/confium
#
# The formula builds the Rust CLI from source via cargo. Pre-built
# bottles will ship once CI produces them per platform.

class Confium < Formula
  desc "Threshold cryptography framework — CLI"
  homepage "https://www.confium.org/"
  url "https://github.com/confium/confium/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "BSD-2-Clause"
  head "https://github.com/confium/confium.git", branch: "main"

  # Rust is required to build from source.
  depends_on "rust" => :build

  # The CLI binary is the only thing this formula installs. The Ruby
  # gem, Python wheel, Node package, and WASM blob each ship via
  # their respective language ecosystems:
  #   gem install confium
  #   pip install confium
  #   npm install @confium/confium-node
  #   npm install @confium/confium-wasm

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/confium-cli")
  end

  test do
    # Smoke-test: version string is non-empty.
    assert_match(/\A\d+\.\d+\.\d+/, shell_output("#{bin}/confium version"))

    # Smoke-test: `tc keygen` produces valid JSON with the expected
    # envelope shape.
    output = shell_output("#{bin}/confium tc keygen --scheme cmp20 --threshold 2 --party-count 3")
    require "json"
    require "tempfile"
    json = JSON.parse(output)
    assert_equal("CMP20", json.fetch("scheme"))
    assert_equal(2, json.fetch("threshold"))
    assert_equal(3, json.fetch("party_count"))
    assert_equal(3, json.fetch("shares").length)
    assert_equal(66, json.fetch("public_key").length)
  end
end
