# frozen_string_literal: true

require "confium"

RSpec.describe Confium::ERS::EvidenceRecord do
  let(:hash) { ("\x42".b * 32).force_encoding("BINARY") }

  describe ".build_initial" do
    it "creates an evidence record" do
      record = described_class.build_initial(hash, "test-tsa", "token-bytes")
      expect(record).to be_a(described_class)
      expect(record.renewal_count).to be >= 1
    end

    it "rejects short hash" do
      expect {
        described_class.build_initial("short", "tsa", "token")
      }.to raise_error(ArgumentError, /32 bytes/)
    end
  end

  describe "#renew" do
    it "returns a new record with incremented count" do
      record = described_class.build_initial(hash, "tsa-1", "token-1")
      initial = record.renewal_count
      renewed = record.renew(hash, "tsa-2", "token-2")
      expect(renewed.renewal_count).to eq(initial + 1)
    end

    it "does not mutate the original" do
      record = described_class.build_initial(hash, "tsa", "token")
      original_count = record.renewal_count
      record.renew(hash, "tsa-2", "new-token")
      expect(record.renewal_count).to eq(original_count)
    end
  end
end
