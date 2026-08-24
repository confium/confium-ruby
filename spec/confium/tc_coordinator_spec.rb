# frozen_string_literal: true

require 'confium'
require 'openssl'

RSpec.describe Confium::TC::Coordinator do
  let(:kg) { Confium::TC::Cmp20.keygen(2, 3) }
  let(:coordinator) { described_class.new(quorum_id: 'test-quorum') }

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

  describe '#aggregate' do
    it 'produces a real ECDSA signature via CMP20' do
      sid = coordinator.create_session(message: 'coordinated', threshold: 2)
      kg['shares'].first(2).each_with_index do |share, i|
        coordinator.submit_commitment(sid, "signer-#{i}", "commitment-#{i}")
        coordinator.submit_share(sid, "signer-#{i}", share)
      end

      signature = coordinator.aggregate(sid)
      expect(signature.bytesize).to eq(64)
      expect(openssl_verify(kg['public_key'], signature, 'coordinated')).to be(true)
      expect(coordinator.session_state(sid)).to be(:completed)
    end

    it 'dispatches to GG18 when the scheme is selected' do
      gg18_kg = Confium::TC::Gg18.keygen(2, 3)
      sid = coordinator.create_session(message: 'gg18 mode', threshold: 2, scheme: 'GG18-ECDSA-P256')
      gg18_kg['shares'].first(2).each_with_index do |share, i|
        coordinator.submit_share(sid, "signer-#{i}", share)
      end

      signature = coordinator.aggregate(sid)
      expect(signature.bytesize).to eq(64)
      expect(openssl_verify(gg18_kg['public_key'], signature, 'gg18 mode')).to be(true)
    end

    it 'raises ThresholdError below the threshold' do
      sid = coordinator.create_session(message: 'too few', threshold: 3)
      coordinator.submit_share(sid, 'signer-0', kg['shares'].first)
      expect { coordinator.aggregate(sid) }
        .to raise_error(Confium::ThresholdError, /Threshold not met/)
    end

    it 'raises on an unknown session' do
      expect { coordinator.aggregate('nope') }.to raise_error(RuntimeError, /Unknown session/)
    end
  end

  describe '#create_session' do
    it 'rejects an unknown scheme' do
      expect { coordinator.create_session(message: 'x', threshold: 1, scheme: 'FROST-ed25519') }
        .to raise_error(ArgumentError, /unknown scheme/)
    end

    it 'transitions to commitments_collected once T commitments arrive' do
      sid = coordinator.create_session(message: 'x', threshold: 2)
      coordinator.submit_commitment(sid, 'a', 'c1')
      expect(coordinator.session_state(sid)).to be(:pending)
      coordinator.submit_commitment(sid, 'b', 'c2')
      expect(coordinator.session_state(sid)).to be(:commitments_collected)
    end
  end
end
