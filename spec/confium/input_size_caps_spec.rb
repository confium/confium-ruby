# frozen_string_literal: true

require "confium"

# Verifies TODO.completion/026-input-size-caps.md — the 1 MiB cap on
# any byte input reaching the Rust extension.
RSpec.describe "Input size caps" do
  it "rejects a 2 MiB PEM cert" do
    big = String.new("a" * (2 * 1024 * 1024), encoding: Encoding::ASCII_8BIT)
    expect {
      Confium::PKI::Certificate.from_pem(big)
    }.to raise_error(ArgumentError, /input size.*exceeds max/)
  end

  it "rejects a 2 MiB array of integers" do
    big = Array.new(2 * 1024 * 1024) { 0 }
    expect {
      Confium::PKI::Certificate.from_der(big)
    }.to raise_error(ArgumentError, /input size.*exceeds max/)
  end

  it "accepts a 1 KiB input (well under the cap)" do
    pem = "-----BEGIN CERTIFICATE-----\n" + ("A" * 1024) + "\n-----END CERTIFICATE-----\n"
    # Just verify we don't crash on input size; parsing will fail separately
    # but NOT with an input-size error.
    expect {
      Confium::PKI::Certificate.from_pem(pem)
    }.to raise_error(RuntimeError) # parse error, not size error
  end
end
