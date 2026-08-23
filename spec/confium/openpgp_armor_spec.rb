# frozen_string_literal: true

require 'confium'
require 'json'

# Differential tests: every vector was captured from the native
# rnp-backed implementation before it was replaced by this pure-Ruby
# one (spec/fixtures/capture_armor_vectors.rb). The wire format must
# not drift.
RSpec.describe Confium::OpenPGP do
  vectors = JSON.parse(File.read(File.expand_path('../fixtures/openpgp_armor_vectors.json', __dir__)))

  describe '.armor' do
    vectors.select { |name, _| !name.start_with?('dearmor_') && !name.end_with?('_roundtrip') }.each do |name, v|
      it "matches the native output byte-for-byte (#{name})" do
        data = [v['input_hex']].pack('H*')
        expect(described_class.armor(data, v['type'])).to eq(v['armored'])
      end
    end

    it 'defaults to the MESSAGE armor type' do
      expect(described_class.armor('x').include?('BEGIN PGP MESSAGE')).to be(true)
    end

    it 'raises ArgumentError for an unknown type' do
      expect { described_class.armor('x', 'nonsense') }.to raise_error(ArgumentError, /unknown armor type/)
    end
  end

  describe '.dearmor' do
    vectors.select { |name, _| name.start_with?('dearmor_') || name.end_with?('_roundtrip') }.each do |name, v|
      it "returns the original bytes (#{name})" do
        expect(described_class.dearmor(v['armored'])).to eq([v['output_hex']].pack('H*'))
      end
    end

    it 'accepts LF-only line endings' do
      lf = described_class.armor('line endings').tr("\r\n", "\n")
      expect(described_class.dearmor(lf)).to eq('line endings')
    end

    it 'raises ParseError without a BEGIN line' do
      expect { described_class.dearmor('just text') }.to raise_error(Confium::ParseError, /BEGIN/)
    end

    it 'raises ParseError without an END line' do
      armored = described_class.armor('truncated')
      expect { described_class.dearmor(armored.sub(/-----END.*-----\r\n/, '')) }
        .to raise_error(Confium::ParseError, /END/)
    end

    it 'raises ParseError on a CRC mismatch' do
      armored = described_class.armor('tamper me')
      bad_crc = armored.sub(%r{=[A-Za-z0-9+/]{4}\r\n-----END}, "=AAAA\r\n-----END")
      expect { described_class.dearmor(bad_crc) }.to raise_error(Confium::ParseError, /CRC/)
    end

    it 'raises ParseError on invalid base64 content' do
      armored = described_class.armor('data').gsub(/^Z.*$/, '!!!not-base64!!!')
      expect { described_class.dearmor(armored) }.to raise_error(Confium::ParseError, /invalid armor data/)
    end
  end

  describe 'round-trip' do
    [0, 1, 47, 48, 96, 1000].each do |size|
      it "survives #{size}-byte payloads" do
        data = (0...size).map { |i| ((i * 7) + 3) & 0xFF }.pack('C*')
        expect(described_class.dearmor(described_class.armor(data))).to eq(data)
      end
    end
  end
end
