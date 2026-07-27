# frozen_string_literal: true

require "confium"

RSpec.describe Confium::Policy do
  after { described_class.reset! }

  describe ".jurisdiction" do
    it "is nil by default" do
      expect(described_class.jurisdiction).to be_nil
    end

    it "accepts :eu" do
      described_class.jurisdiction = :eu
      expect(described_class.jurisdiction).to eq(:eu)
    end

    it "rejects unknown jurisdiction" do
      expect {
        described_class.jurisdiction = :mars
      }.to raise_error(ArgumentError, /unknown jurisdiction/)
    end

    it "resets to nil" do
      described_class.jurisdiction = :eu
      described_class.jurisdiction = nil
      expect(described_class.jurisdiction).to be_nil
    end
  end

  describe ".fips_mode" do
    it "is false by default" do
      expect(described_class.fips_mode).to be(false)
    end

    it "enables and sets jurisdiction to :us" do
      described_class.fips_mode = true
      expect(described_class.fips_mode).to be(true)
      expect(described_class.jurisdiction).to eq(:us)
    end
  end

  describe ".check!" do
    it "passes when no policy is set" do
      expect(described_class.check!("ecdsa_p256", key_bits: 256)).to be(true)
    end

    it "passes for EU with P-256" do
      described_class.jurisdiction = :eu
      expect(described_class.check!("ecdsa_p256", key_bits: 256)).to be(true)
    end

    it "raises PolicyViolationError for EU with RSA-1024" do
      described_class.jurisdiction = :eu
      expect {
        described_class.check!("rsa", key_bits: 1024)
      }.to raise_error(Confium::PolicyViolationError, /key size 1024 below 2048/)
    end

    it "raises PolicyViolationError for FIPS mode with Ed25519" do
      described_class.fips_mode = true
      expect {
        described_class.check!("ed25519", key_bits: 256)
      }.to raise_error(Confium::PolicyViolationError, /not FIPS-approved/)
    end
  end

  describe ".known_jurisdictions" do
    it "returns the three built-in jurisdictions" do
      expect(described_class.known_jurisdictions).to include(:eu, :us, :cnml)
    end
  end
end
