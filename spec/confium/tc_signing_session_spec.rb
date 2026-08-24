# frozen_string_literal: true

require 'confium'
require 'openssl'

RSpec.describe Confium::TC::SigningSession do
  let(:kg) { Confium::TC::Cmp20.keygen(2, 3) }
  let(:session) do
    described_class.new(message: 'direct', threshold: 2)
  end

  def pkey_from(public_key_bytes)
    asn1 = OpenSSL::ASN1::Sequence([
                                     OpenSSL::ASN1::Sequence([
                                                               OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                               OpenSSL::ASN1::ObjectId('prime256v1')
                                                             ]),
                                     OpenSSL::ASN1::BitString(public_key_bytes)
                                   ])
    OpenSSL::PKey::EC.new(asn1.to_der)
  end

  def openssl_verify(public_key_bytes, signature, message)
    r = OpenSSL::BN.new(signature[0, 32], 2)
    s = OpenSSL::BN.new(signature[32, 32], 2)
    der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
    pkey_from(public_key_bytes).dsa_verify_asn1(OpenSSL::Digest.digest('SHA256', message), der)
  end

  describe 'state machine' do
    it 'starts pending' do
      expect(session.state).to be(:pending)
      expect(session.threshold_met?).to be(false)
    end

    it 'collects commitments from distinct signers and reports the transition' do
      session.add_commitment('a', 'c1')
      expect(session.state).to be(:pending)
      expect(session.commitment_count).to eq(1)

      session.add_commitment('b', 'c2')
      expect(session.state).to be(:commitments_collected)
    end

    it 'completes on aggregate once the share threshold is met' do
      kg['shares'].first(2).each_with_index { |share, i| session.add_share("signer-#{i}", share) }

      signature = session.aggregate
      expect(session.state).to be(:completed)
      expect(signature.bytesize).to eq(64)
      expect(openssl_verify(kg['public_key'], signature, 'direct')).to be(true)
    end

    it 're-aggregates after completion (the combine is randomized, each call is valid)' do
      kg['shares'].first(2).each_with_index { |share, i| session.add_share("signer-#{i}", share) }

      first = session.aggregate
      second = session.aggregate
      expect(first.bytesize).to eq(64)
      expect(second.bytesize).to eq(64)
      expect(openssl_verify(kg['public_key'], second, 'direct')).to be(true)
    end
  end

  describe 'signer identity' do
    it 'rejects a duplicate commitment from the same signer' do
      session.add_commitment('a', 'c1')
      expect { session.add_commitment('a', 'c2') }
        .to raise_error(Confium::ValidationError, /duplicate submission/)
    end

    it 'rejects a duplicate share from the same signer' do
      session.add_share('a', kg['shares'].first)
      expect { session.add_share('a', kg['shares'][1]) }
        .to raise_error(Confium::ValidationError, /duplicate submission/)
    end

    it 'never lets one signer satisfy the threshold alone' do
      expect { session.add_share('a', kg['shares'].first) }
        .not_to raise_error
      expect { session.add_share('a', kg['shares'][1]) }
        .to raise_error(Confium::ValidationError)
      expect(session.share_count).to eq(1)
      expect { session.aggregate }
        .to raise_error(Confium::ThresholdError, /Threshold not met/)
    end
  end

  describe '#aggregate below threshold' do
    it 'raises ThresholdError with have/need counts' do
      session.add_share('a', kg['shares'].first)
      begin
        session.aggregate
        raise 'expected aggregate to raise'
      rescue Confium::ThresholdError => e
        expect(e.have_count).to eq(1)
        expect(e.need_count).to eq(2)
      end
    end
  end

  describe 'scheme validation' do
    it 'rejects an unknown scheme at construction' do
      expect { described_class.new(message: 'x', threshold: 1, scheme: 'FROST-ed25519') }
        .to raise_error(ArgumentError, /unknown scheme/)
    end

    it 'combines via GG18 when the scheme is selected' do
      gg18_kg = Confium::TC::Gg18.keygen(2, 3)
      gg18 = described_class.new(message: 'gg18', threshold: 2, scheme: 'GG18-ECDSA-P256')
      gg18_kg['shares'].first(2).each_with_index { |share, i| gg18.add_share("signer-#{i}", share) }

      expect(openssl_verify(gg18_kg['public_key'], gg18.aggregate, 'gg18')).to be(true)
    end
  end
end
