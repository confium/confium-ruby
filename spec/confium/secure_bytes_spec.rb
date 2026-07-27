# frozen_string_literal: true

require "confium"

# Verifies TODO.completion/028-zeroize-on-drop.md — Confium::SecureBytes
# wraps sensitive data with zeroize-on-clear.
RSpec.describe Confium::SecureBytes do
  let(:secret) { described_class.wrap("sensitive-key-bytes-32b-long!!".b) }

  describe ".wrap" do
    it "creates a SecureBytes from a String" do
      expect(secret).to be_a(described_class)
      expect(secret.length).to eq(30)
    end
  end

  describe "#bytes" do
    it "returns a copy of the wrapped bytes" do
      copy = secret.bytes
      expect(copy).to eq("sensitive-key-bytes-32b-long!!".b)
      expect(copy.encoding).to eq(Encoding::ASCII_8BIT)
      # Modifying the copy must not affect the original.
      copy.replace("X" * 30)
      expect(secret.bytes).to eq("sensitive-key-bytes-32b-long!!".b)
    end

    it "raises ClearedError after #clear" do
      secret.clear
      expect { secret.bytes }.to raise_error(Confium::SecureBytes::ClearedError)
    end
  end

  describe "#bytes!" do
    it "returns a copy then clears the original" do
      copy = secret.bytes!
      expect(copy).to eq("sensitive-key-bytes-32b-long!!".b)
      expect(secret.cleared?).to be(true)
      expect(secret.length).to eq(0)
    end
  end

  describe "#clear" do
    it "zeroizes the buffer" do
      secret.clear
      expect(secret.cleared?).to be(true)
    end

    it "is idempotent" do
      secret.clear
      secret.clear  # should not raise
      expect(secret.cleared?).to be(true)
    end
  end

  describe "#inspect" do
    it "shows byte count when active" do
      expect(secret.inspect).to match(/30 bytes/)
    end

    it "shows CLEARED after clear" do
      secret.clear
      expect(secret.inspect).to match(/CLEARED/)
    end
  end

  describe "integration with keypair generation" do
    it "can wrap a generated private key" do
      kp = Confium::TC::FrostP256.generate_keypair
      wrapped = described_class.wrap(kp["private_key"])
      expect(wrapped.bytes.bytesize).to eq(32)
      wrapped.clear
      expect(wrapped.cleared?).to be(true)
    end
  end
end
