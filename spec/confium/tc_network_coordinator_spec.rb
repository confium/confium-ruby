# frozen_string_literal: true

require 'confium'
require 'openssl'

RSpec.describe Confium::TC::NetworkCoordinator do
  let(:kg) { Confium::TC::Cmp20.keygen(2, 3) }
  let(:service) { described_class.new(quorum_id: 'spec-quorum').start }
  let(:port) { service.port }

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

  after { service.stop }

  describe 'multi-signer signing over separate connections' do
    it 'collects shares from concurrent signers and produces a verifiable signature' do
      coordinator_client = Confium::TC::SignerClient.new(port: port)
      sid = coordinator_client.create_session(message: 'distributed', threshold: 2)

      signers = kg['shares'].first(2).each_with_index.map do |share, i|
        Thread.new do
          client = Confium::TC::SignerClient.new(port: port)
          client.submit_commitment(sid, "signer-#{i}", "commitment-#{i}")
          client.submit_share(sid, "signer-#{i}", share)
        end
      end
      signers.each(&:join)

      signature = coordinator_client.aggregate(sid)
      expect(signature.bytesize).to eq(64)
      expect(openssl_verify(kg['public_key'], signature, 'distributed')).to be(true)
    end
  end

  describe 'error mapping' do
    it 'surfaces ThresholdError from below-threshold aggregation' do
      client = Confium::TC::SignerClient.new(port: port)
      sid = client.create_session(message: 'too few', threshold: 3)
      client.submit_share(sid, 'signer-0', kg['shares'].first)

      expect { client.aggregate(sid) }
        .to raise_error(Confium::TC::SignerClient::RemoteError, /ThresholdError.*Threshold not met/)
    end

    it 'rejects unknown operations' do
      expect do
        Confium::TC::SignerClient.new(port: port).send(:call, 'op' => 'explode')
      end.to raise_error(Confium::TC::SignerClient::RemoteError, /unknown op/)
    end
  end

  describe '#stop' do
    it 'shuts the listener down' do
      expect(service.running?).to be(true)
      service.stop
      expect(service.running?).to be(false)
      expect { Confium::TC::SignerClient.new(port: port).send(:call, 'op' => 'create') }
        .to raise_error(Errno::ECONNREFUSED)
    end
  end
end
