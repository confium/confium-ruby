# frozen_string_literal: true

require 'confium'

# Confium::OpenPGP is now a NATIVE extension module backed by bundled
# rnp-rs (OpenPGP, RFC 9580). No external gem dependency required.
RSpec.describe Confium::OpenPGP do
  describe 'constants' do
    it 'exposes armor type constants' do
      expect(Confium::OpenPGP::MESSAGE).to eq('message')
      expect(Confium::OpenPGP::PUBLIC_KEY).to eq('public key')
      expect(Confium::OpenPGP::SECRET_KEY).to eq('secret key')
      expect(Confium::OpenPGP::SIGNATURE).to eq('signature')
      expect(Confium::OpenPGP::CLEARTEXT).to eq('cleartext signed message')
    end
  end

  describe '.armor' do
    it 'ASCII-armors raw bytes as a message by default' do
      result = described_class.armor('hello world')
      expect(result).to include('-----BEGIN PGP MESSAGE-----')
      expect(result).to include('-----END PGP MESSAGE-----')
    end

    it 'accepts a type argument for different armor headers' do
      result = described_class.armor('test data', Confium::OpenPGP::SIGNATURE)
      expect(result).to include('-----BEGIN PGP SIGNATURE-----')
    end

    it 'accepts public_key type' do
      result = described_class.armor('key data', Confium::OpenPGP::PUBLIC_KEY)
      expect(result).to include('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    end
  end

  describe '.dearmor' do
    it 'decodes armored data back to raw bytes' do
      armored = described_class.armor('round trip test')
      decoded = described_class.dearmor(armored)
      expect(decoded).to eq('round trip test')
    end

    it 'raises on non-armored input' do
      expect do
        described_class.dearmor('not armored data')
      end.to raise_error(Confium::ParseError)
    end
  end

  describe '.armor + .dearmor round-trip' do
    it 'preserves binary data' do
      binary_data = ("\x00\x01\x02\xFF\xFE".b * 10)
      armored = described_class.armor(binary_data)
      decoded = described_class.dearmor(armored)
      expect(decoded).to eq(binary_data)
    end
  end
end
