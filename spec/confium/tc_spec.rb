# frozen_string_literal: true

require 'confium'

RSpec.describe Confium::TC::FrostP256 do
  describe '.generate_keypair' do
    it 'returns a 32-byte private key and 65-byte SEC1 public key' do
      kp = described_class.generate_keypair
      expect(kp['private_key'].bytesize).to eq(32)
      expect(kp['public_key'].bytesize).to eq(65)
    end

    it 'produces a fresh keypair each call' do
      kp1 = described_class.generate_keypair
      kp2 = described_class.generate_keypair
      expect(kp1['private_key']).not_to eq(kp2['private_key'])
    end
  end

  describe '.split_secret + .recover_secret' do
    let(:secret) { described_class.generate_keypair['private_key'] }

    it 'round-trips a 32-byte secret through a 3-of-5 split' do
      shares = described_class.split_secret(secret, 3, 5)
      expect(shares.size).to eq(5)
      expect(shares.map(&:x)).to eq([1, 2, 3, 4, 5])

      # Any 3 of 5 should reconstruct the secret.
      [0, 2, 4].each do |i|
        subset = [shares[i], shares[(i + 1) % 5], shares[(i + 2) % 5]]
        recovered = described_class.recover_secret(
          subset.map { |s| { 'x' => s.x, 'y' => s.y_bytes } }
        )
        expect(recovered).to eq(secret)
      end
    end

    it 'produces a wrong secret when fewer than threshold shares are used' do
      # Lagrange interpolation with < t shares returns a value, just not
      # the original secret. The point of threshold is that fewer shares
      # reveal nothing useful — confirm the recovered bytes differ.
      shares = described_class.split_secret(secret, 3, 5).first(2)
      recovered = described_class.recover_secret(
        shares.map { |s| { 'x' => s.x, 'y' => s.y_bytes } }
      )
      expect(recovered).not_to eq(secret)
    end

    it "rejects a secret that isn't 32 bytes" do
      expect do
        described_class.split_secret('x' * 16, 3, 5)
      end.to raise_error(ArgumentError, /must be exactly 32 bytes/)
    end
  end

  describe '.sign' do
    let(:kp) { described_class.generate_keypair }

    it 'returns DER and fixed-size signature bytes' do
      sig = described_class.sign(kp['private_key'], 'hello')
      expect(sig['der'].bytesize).to be > 0
      expect(sig['fixed'].bytesize).to eq(64)
    end

    it 'produces different signatures for different messages' do
      sig1 = described_class.sign(kp['private_key'], 'msg1')
      sig2 = described_class.sign(kp['private_key'], 'msg2')
      expect(sig1['fixed']).not_to eq(sig2['fixed'])
    end

    it "rejects private keys that aren't 32 bytes" do
      expect do
        described_class.sign('x' * 16, 'hello')
      end.to raise_error(ArgumentError, /private key must be 32 bytes/)
    end
  end

  describe Confium::TC::FrostP256::Share do
    it 'exposes x and y_bytes accessors' do
      secret = Confium::TC::FrostP256.generate_keypair['private_key']
      share = Confium::TC::FrostP256.split_secret(secret, 2, 2).first
      expect(share.x).to eq(1)
      expect(share.y_bytes.bytesize).to eq(32)
      expect(share.y_bytes.encoding).to eq(Encoding::ASCII_8BIT)
    end
  end
end

RSpec.describe Confium::TC::ElGamalP256 do
  describe '.encapsulate + .partial_decrypt + .aggregate_partials' do
    it 'round-trips a 3-of-5 threshold decryption' do
      kp = Confium::TC::FrostP256.generate_keypair
      shares = Confium::TC::FrostP256.split_secret(kp['private_key'], 3, 5)

      encap = described_class.encapsulate(kp['public_key'])
      expect(encap['shared_secret'].bytesize).to eq(32)
      expect(encap['ciphertext']).to be_a(Hash)
      expect(encap['ciphertext']['c1'].bytesize).to eq(65)
      expect(encap['ciphertext']['c2'].bytesize).to eq(65)

      partials = shares.first(3).map do |share|
        described_class.partial_decrypt(share.x, share.y_bytes, encap['ciphertext'])
      end
      expect(partials.size).to eq(3)
      partials.each do |p|
        expect(p['party_index']).to be_a(Integer)
        expect(p['bytes'].bytesize).to eq(65)
      end

      recovered = described_class.aggregate_partials(partials, 3, encap['ciphertext'])
      expect(recovered).to eq(encap['shared_secret'])
    end
  end
end
