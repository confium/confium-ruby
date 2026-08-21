#!/usr/bin/env ruby
# frozen_string_literal: true

#
# RFC 3161 timestamping use case — produce threshold-signed RFC 3161
# timestamps for long-term archival. Multiple TSAs (Time-Stamping
# Authorities) cooperate to produce a single timestamp token; if any
# single TSA goes offline or is compromised, the others can still
# issue timestamps.
#
# Why threshold signing for timestamps?
#
#   - **TSA key compromise is high-impact**: anyone with a TSA key
#     can backdate documents, breaking non-repudiation for every
#     timestamp that TSA ever issued.
#   - **Operational continuity**: if a TSA goes bankrupt / gets
#     acquired / changes business model, existing timestamps still
#     verify under the joint key.
#   - **Compliance**: government and legal archives require
#     long-term-durable timestamps. Threshold signing + transparency
#     log anchoring is the gold standard.
#
# This example uses Confium's threshold-ECDSA as the signing primitive.
# RFC 3161 normally uses RSA-PSS or ECDSA over a TSA-issued cert;
# the threshold case works identically — just use the joint public
# key in the TSA's X.509 cert.

require 'digest'
require 'json'
require 'tmpdir'
require 'time'
require 'securerandom'
require 'confium'

puts '== Setup: TSA cluster threshold key =='
kg = Confium::TC::Cmp20.keygen(2, 3)
puts "  TSA joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  TSA shares held by: tsa_primary, tsa_backup, tsa_audit'

puts
puts '== Client requests timestamp for a hash =='
document_hash = Digest::SHA256.digest('important legal document content')
puts "  document SHA-256: #{Digest::SHA256.hexdigest('important legal document content')[0, 24]}..."

# RFC 3161 TimeStampReq:
#   version, messageImprint (hash algo + hash), reqPolicy, nonce, certReq
request = {
  version: 1,
  message_imprint: {
    hash_algorithm: '2.16.840.1.101.3.4.2.1', # SHA-256 OID
    hashed_message: document_hash.unpack1('H*')
  },
  nonce: SecureRandom.random_number(2**64).to_s,
  cert_req: true
}

puts
puts '== TSA cluster: 2-of-3 threshold-sign the timestamp token =='
# The timestamp token (RFC 3161 TimeStampResp) contains:
#   status, timeStampToken (CMS SignedData with the signed TSTInfo)
# We sign the TSTInfo content (the structured timestamp info) directly
# for this example; production wraps it in CMS SignedData per RFC 5652.
tst_info = {
  version: 1,
  policy: '1.2.3.4.1', # TSA policy OID
  message_imprint: request[:message_imprint],
  serial_number: 1_234_567,
  gen_time: Time.now.utc.iso8601,
  accuracy: { seconds: 1, millis: 0, micros: 0 },
  ordering: false,
  nonce: request[:nonce],
  tsa: 'tsa@example.com'
}
tst_info_json = JSON.generate(tst_info)

two_shares = kg['shares'].first(2)
sig = Confium::TC::Cmp20.sign(two_shares, 2, tst_info_json)
puts "  timestamp signature: 0x#{sig.unpack1('H*')[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts '== Verifier checks timestamp against TSA joint public key =='
require 'openssl'
asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(kg['public_key'])
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(sig[0, 32], 2)
s = OpenSSL::BN.new(sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(tst_info_json)

if pkey.dsa_verify_asn1(digest, der)
  puts "  ✓ timestamp verified — document existed at #{tst_info[:gen_time]}"
  puts "  TSA joint key (#{tst_info[:tsa]}) confirms existence at the stated time"
else
  abort '  ✗ timestamp FAILED'
end

puts
puts '== ERS archival (RFC 4998) =='
# Long-term archival: wrap the timestamp in an Evidence Record Syntax
# (RFC 4998) envelope, with renewals every 5-10 years as crypto
# primitives age out. Confium's ERS module handles this:
archived_hash = Digest::SHA256.digest(tst_info_json + sig)
ers = Confium::ERS::EvidenceRecord.build_initial(archived_hash, 'tsa_joint', sig)
puts "  ERS record created with renewal count: #{ers.renewal_count}"
puts '  (renew every 5-10 years with a fresh TSA signature as old algorithms age out)'

puts
puts '== Transparency log anchor =='
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(tst_info_json))
puts "  transparency root: 0x#{tree.root.unpack1('H*')[0, 24]}..."
puts
puts "Done. The document's existence at #{tst_info[:gen_time]} is"
puts 'cryptographically timestamped by a 2-of-3 TSA quorum, wrapped in'
puts 'an ERS envelope for archival, and anchored to a transparency log.'
