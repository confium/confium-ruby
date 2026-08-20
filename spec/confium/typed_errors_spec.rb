# frozen_string_literal: true

require "confium"

# Verify the typed-error hierarchy carries structured context from the
# native extension through to Ruby accessor methods. Each error class
# must accept `(msg, details_hash)` positionally (the form the native
# extension uses via magnus funcall) and expose its specific fields via
# `attr_reader`.
RSpec.describe "Confium typed errors" do
  describe Confium::ThresholdError do
    it "exposes have_count / need_count from native extension path" do
      kg = Confium::TC::Cmp20.keygen(3, 5)
      begin
        Confium::TC::Cmp20.sign(kg["shares"].first(2), 3, "msg")
        fail "should have raised"
      rescue described_class => e
        expect(e.have_count).to eq(2)
        expect(e.need_count).to eq(3)
        expect(e.message).to match(/Threshold/)
        expect(e.details[:have_count]).to eq(2)
        expect(e.details[:need_count]).to eq(3)
        expect(e.details[:operation]).to eq("Cmp20.sign")
      end
    end

    it "also constructs directly via keyword form" do
      e = described_class.new("insufficient", have_count: 1, need_count: 5)
      expect(e.have_count).to eq(1)
      expect(e.need_count).to eq(5)
    end
  end

  describe Confium::VerificationError do
    it "exposes signer_index / algorithm from the helper" do
      # Verify the helper produces a usable instance when called from Ruby
      # (the native extension does the same call internally).
      instance = described_class.new("bad sig", {
        signer_index: 2,
        algorithm: "Ed25519",
        operation: "Composite.verify",
      })
      expect(instance.signer_index).to eq(2)
      expect(instance.algorithm).to eq("Ed25519")
      expect(instance.details[:operation]).to eq("Composite.verify")
    end
  end

  describe Confium::CryptoError do
    it "exposes primitive from the helper" do
      instance = described_class.new("kdf failed", { primitive: "hkdf", operation: "derive" })
      expect(instance.primitive).to eq("hkdf")
    end
  end

  describe Confium::ValidationError do
    it "exposes param / expected / actual from the helper" do
      instance = described_class.new("bad size", {
        param: "data_hash",
        expected: "32 bytes",
        actual: "10 bytes",
      })
      expect(instance.param).to eq("data_hash")
      expect(instance.expected).to eq("32 bytes")
      expect(instance.actual).to eq("10 bytes")
    end
  end

  describe Confium::ParseError do
    it "exposes format / offset from the helper" do
      instance = described_class.new("bad PEM", { format: "pem", offset: 5 })
      expect(instance.format).to eq("pem")
      expect(instance.offset).to eq(5)
    end
  end

  describe Confium::NotFoundError do
    it "exposes kind / identifier from the helper" do
      instance = described_class.new("missing", { kind: "certificate", identifier: "abc" })
      expect(instance.kind).to eq("certificate")
      expect(instance.identifier).to eq("abc")
    end
  end

  describe Confium::IndexError do
    it "exposes index / valid_range from the helper" do
      instance = described_class.new("oob", { index: 99, valid_range: 0..4 })
      expect(instance.index).to eq(99)
      expect(instance.valid_range).to eq(0..4)
    end
  end

  describe Confium::PolicyViolationError do
    it "exposes policy / violation from the helper" do
      instance = described_class.new("FIPS", { policy: "FIPS-140", violation: "non-approved alg" })
      expect(instance.policy).to eq("FIPS-140")
      expect(instance.violation).to eq("non-approved alg")
    end
  end

  describe Confium::UnresolvedSignerError do
    it "exposes signer_index from the helper" do
      instance = described_class.new("no cert", { signer_index: 3 })
      expect(instance.signer_index).to eq(3)
    end
  end

  describe Confium::Error do
    it "is the root of the hierarchy" do
      expect(Confium::ThresholdError.ancestors).to include(described_class)
      expect(Confium::CryptoError.ancestors).to include(described_class)
      expect(described_class.ancestors).to include(StandardError)
    end

    it "carries details Hash" do
      e = described_class.new("msg", details: { foo: 1 })
      expect(e.details[:foo]).to eq(1)
    end
  end
end
