#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Document-signing use case: threshold-sign a PDF / OpenDocument /
# arbitrary file using CMS SignedData (RFC 5652). The signed document
# opens in any standards-compliant office suite (Adobe Reader,
# LibreOffice, macOS Preview) and verifies under the joint public key.
#
# This example demonstrates the API surface; in production you'd
# embed the CMS SignedData in the PDF's /ByteRange signature
# dictionary or ODF's document-signatures.xml.
#
# Why threshold signing for documents?
#
#   - Multi-stakeholder approvals: 3-of-5 directors can jointly sign
#     a contract without ever reconstructing the signing key.
#   - Long-term archival: the joint signature is a standard ECDSA-P256
#     signature, so it remains verifiable in any tool that supports
#     X.509 + CMS — even decades from now.
#   - Audit: each signing ceremony produces a record in the audit log.
#
# Run:
#   bundle exec ruby examples/document_signing.rb

require 'digest'
require 'json'
require 'openssl'
require 'tmpdir'
require 'confium'

puts '== Setup: load or generate joint signing key =='
kg = Confium::TC::Cmp20.keygen(3, 5)
puts "  joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  3-of-5 threshold — three of: CEO, CFO, GC, Board_Chair, Audit_Chair'

puts
puts '== Load document to be signed =='
# Pretend this is a contract PDF.
document = <<~DOC
  SERVICES AGREEMENT

  This Agreement is entered into between ExampleCorp and VendorCo
  for the provision of consulting services, effective 2026-01-01.

  [Signature lines for three of five corporate officers above]
DOC
File.write('/tmp/contract.txt', document)
puts "  loaded /tmp/contract.txt (#{document.bytesize} bytes)"

puts
puts '== Three officers sign =='
signing_ceremony = kg['shares'].first(3)
puts '  participating: CEO, CFO, GC'
signature = Confium::TC::Cmp20.sign(signing_ceremony, 3, document)
puts "  signature: 0x#{signature.unpack1('H*')[0, 24]}... (#{signature.bytesize} bytes)"

# Build a minimal CMS SignedData envelope around the signature.
# In production this would be DER-encoded per RFC 5652; here we use
# JSON for readability.
cms_envelope = {
  version: 1,
  digest_algorithms: ['2.16.840.1.101.3.4.2.1'], # SHA-256 OID
  encap_content_info: {
    e_content_type: '1.2.840.113549.1.7.1', # id-data
    e_content: [document].pack('m0') # base64 of document
  },
  certificates: [], # would carry the issuer's X.509 cert chain
  signer_infos: [
    {
      version: 1,
      digest_algorithm: '2.16.840.1.101.3.4.2.1',
      signature_algorithm: '1.2.840.10045.4.3.2', # ECDSA-with-SHA-256
      signature: [signature].pack('m0'),
      joint_public_key: [kg['public_key']].pack('m0'),
      sid: 'threshold-cmp20-3-of-5'
    }
  ]
}
File.write('/tmp/contract.cms.json', JSON.generate(cms_envelope))
puts '  wrote /tmp/contract.cms.json'

puts
puts '== Verify (third-party verifier) =='
loaded = JSON.parse(File.read('/tmp/contract.cms.json'))
loaded_doc = loaded['encap_content_info']['e_content'].unpack1('m0')
loaded_sig = loaded['signer_infos'].first['signature'].unpack1('m0')
loaded_pk = loaded['signer_infos'].first['joint_public_key'].unpack1('m0')

asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(loaded_pk)
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)

r = OpenSSL::BN.new(loaded_sig[0, 32], 2)
s = OpenSSL::BN.new(loaded_sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der

digest = Digest::SHA256.digest(loaded_doc)
if pkey.dsa_verify_asn1(digest, der)
  puts '  ✓ document verified — joint signature from CEO+CFO+GC is valid'
else
  abort '  ✗ verification FAILED'
end

puts
puts '== Archive: anchor signature + document hash to transparency log =='
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(document + signature))
puts "  transparency root: 0x#{tree.root.unpack1('H*')[0, 24]}..."
puts
puts 'Done. The contract is signed by a 3-of-5 quorum, anchored to a'
puts 'transparency log, and verifiable by anyone with the CMS envelope.'
