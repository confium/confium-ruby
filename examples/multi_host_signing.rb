#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Multi-host threshold signing: signers in separate processes submit
# commitments and shares to a networked coordinator; once the
# threshold is met the coordinator runs the real CMP20 combine and
# returns a signature verifiable under the quorum public key.
#
# Run with: ruby examples/multi_host_signing.rb
#
# Here each "signer" is a thread with its own client (on separate
# machines they would be separate processes). The wire protocol is
# NDJSON with hex-encoded binary fields.

require 'confium'
require 'openssl'

# 1. Quorum setup (a one-time keygen ceremony in real deployments).
QUORUM_THRESHOLD = 2
kg = Confium::TC::Cmp20.keygen(QUORUM_THRESHOLD, 3)
puts "Quorum: #{QUORUM_THRESHOLD}-of-3, public key #{kg['public_key'].unpack1('H*')[0, 16]}..."

# 2. The coordinator service — on a real network this is its own
#    host (plain TCP today; see TODO.full/01 for the upstream
#    noise-transport plan).
service = Confium::TC::NetworkCoordinator.new(quorum_id: 'example-quorum').start
puts "Coordinator listening on 127.0.0.1:#{service.port}"

# 3. Each signer holds one share and joins the session.
session_creator = Confium::TC::SignerClient.new(port: service.port)
session_id = session_creator.create_session(
  message: 'the deployment payload',
  threshold: QUORUM_THRESHOLD,
  scheme: 'CMP20-ECDSA-P256'
)
puts "Session #{session_id} created"

signers = kg['shares'].first(QUORUM_THRESHOLD).each_with_index.map do |share, i|
  Thread.new do
    client = Confium::TC::SignerClient.new(port: service.port)
    client.submit_commitment(session_id, "signer-#{i}", "commitment-#{i}")
    puts "  signer-#{i}: commitment submitted"
    client.submit_share(session_id, "signer-#{i}", share)
    puts "  signer-#{i}: share submitted"
  end
end
signers.each(&:join)

# 4. Anyone may trigger aggregation once T shares arrived.
signature = session_creator.aggregate(session_id)
service.stop
puts "Aggregated signature (64 bytes): #{signature.unpack1('H*')[0, 24]}..."

# 5. Verify under the quorum public key — no threshold machinery
#    needed by verifiers.
asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(kg['public_key'])
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(signature[0, 32], 2)
s = OpenSSL::BN.new(signature[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
ok = pkey.dsa_verify_asn1(OpenSSL::Digest.digest('SHA256', 'the deployment payload'), der)
puts "Verification under quorum key: #{ok ? 'VALID' : 'INVALID'}"
