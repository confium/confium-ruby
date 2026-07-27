# frozen_string_literal: true

require "confium"

RSpec.describe Confium::Composite do
  describe ".generate_ed25519_keypair" do
    it "returns a 32-byte private key and a 32-byte public key" do
      kp = described_class.generate_ed25519_keypair
      expect(kp["private_key"].bytesize).to eq(32)
      expect(kp["public_key"].bytesize).to eq(32)
    end

    it "produces a fresh keypair each call" do
      kp1 = described_class.generate_ed25519_keypair
      kp2 = described_class.generate_ed25519_keypair
      expect(kp1["private_key"]).not_to eq(kp2["private_key"])
    end
  end

  describe ".sign_ed25519" do
    let(:kp) { described_class.generate_ed25519_keypair }

    it "builds an Ed25519 component signature" do
      comp = described_class.sign_ed25519(kp["private_key"], "hello")
      expect(comp["algorithm"]).to eq("Ed25519")
      expect(comp["public_key"].bytesize).to eq(32)
      expect(comp["signature"].bytesize).to eq(64)
      expect(comp["public_key"]).to eq(kp["public_key"])
    end

    it "rejects private keys that are not 32 bytes" do
      expect {
        described_class.sign_ed25519(("x" * 16), "hello")
      }.to raise_error(ArgumentError, /Ed25519 private key must be 32 bytes/)
    end
  end

  describe "Confium::Composite::Signature" do
    let(:kp) { described_class.generate_ed25519_keypair }
    let(:component) { described_class.sign_ed25519(kp["private_key"], "msg") }

    it "exposes component_count and algorithms" do
      sig = described_class::Signature.new([component])
      expect(sig.component_count).to eq(1)
      expect(sig.algorithms).to eq(["Ed25519"])
    end

    it "verifies a real Ed25519 signature for the right message" do
      sig = described_class::Signature.new([component])
      result = sig.verify("msg")
      expect(result).to be_a(described_class::VerificationResult)
      expect(result.all_verified?).to be(true)
    end

    it "fails verification for the wrong message" do
      sig = described_class::Signature.new([component])
      result = sig.verify("wrong")
      expect(result.all_verified?).to be(false)
      details = result.per_component
      expect(details.size).to eq(1)
      expect(details[0]["verified"]).to be(false)
      expect(details[0]["error"]).to be_a(String)
    end
  end
end
