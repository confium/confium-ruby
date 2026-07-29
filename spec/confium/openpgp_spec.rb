# frozen_string_literal: true

require "confium"

RSpec.describe Confium::OpenPGP do
  describe ".available?" do
    it "returns a boolean" do
      result = described_class.available?
      expect([true, false]).to include(result)
    end
  end

  describe ".ensure_available!" do
    context "when ruby-rnp is not installed" do
      before do
        allow(described_class).to receive(:available?).and_return(false)
      end

      it "raises NotInstalledError with install instructions" do
        expect { described_class.ensure_available! }.to raise_error(
          Confium::OpenPGP::NotInstalledError, /gem install ruby-rnp/
        )
      end
    end
  end

  describe ".verify" do
    context "when ruby-rnp is not installed" do
      before do
        allow(described_class).to receive(:available?).and_return(false)
      end

      it "raises NotInstalledError" do
        expect {
          described_class.verify("sig", "data", "key")
        }.to raise_error(Confium::OpenPGP::NotInstalledError)
      end
    end
  end

  describe ".sign" do
    context "when ruby-rnp is not installed" do
      before do
        allow(described_class).to receive(:available?).and_return(false)
      end

      it "raises NotInstalledError" do
        expect {
          described_class.sign("data", "key_armor")
        }.to raise_error(Confium::OpenPGP::NotInstalledError)
      end
    end
  end

  describe ".generate_key" do
    context "when ruby-rnp is not installed" do
      before do
        allow(described_class).to receive(:available?).and_return(false)
      end

      it "raises NotInstalledError" do
        expect {
          described_class.generate_key("test@example.com")
        }.to raise_error(Confium::OpenPGP::NotInstalledError)
      end
    end
  end

  describe ".encrypt" do
    context "when ruby-rnp is not installed" do
      before do
        allow(described_class).to receive(:available?).and_return(false)
      end

      it "raises NotInstalledError" do
        expect {
          described_class.encrypt("data", "pubkey")
        }.to raise_error(Confium::OpenPGP::NotInstalledError)
      end
    end
  end

  describe "NotInstalledError" do
    it "is a subclass of Confium::Error" do
      expect(Confium::OpenPGP::NotInstalledError.ancestors).to include(Confium::Error)
    end
  end
end
