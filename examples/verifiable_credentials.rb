#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Verifiable Credentials use case — threshold-sign W3C Verifiable
# Credentials (VCs) by an issuer quorum. The credential holder can
# then present it to any verifier, who checks the joint issuer's
# public key.
#
# Why threshold signing for VCs?
#
#   - **Issuer key compromise is catastrophic**: anyone with the
#     issuer's DID signing key can mint fake credentials (fake
#     degrees, fake ID, fake bank records). Threshold signing
#     splits the issuer across multiple parties.
#   - **Decentralized issuers**: a university's "degree-issuing
#     authority" is split across the registrar + academic office +
#     president's office. No single party can issue a degree alone.
#   - **Standards compliance**: W3C VC Data Model 2.0 supports
#     multiple proof types; Confium's threshold-ECDSA-P256 is a
#     drop-in for the `proof` field.
#
# Run: `bundle exec ruby examples/verifiable_credentials.rb`

require 'base64'
require 'digest'
require 'json'
require 'confium'

puts '== Setup: issuer quorum threshold key =='
kg = Confium::TC::Cmp20.keygen(2, 3)
issuer_did = 'did:web:example.edu:registrar'
puts "  issuer: #{issuer_did}"
puts "  joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  issuer shares held by: registrar, academic_office, university_president'

puts
puts '== Build the credential (W3C VC Data Model 2.0) =='
credential = {
  '@context' => [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2'
  ],
  id: 'https://example.edu/credentials/3732',
  type: %w[VerifiableCredential ExampleAlumniCredential],
  issuer: issuer_did,
  issuanceDate: '2026-07-31T00:00:00Z',
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    alumniOf: {
      id: 'did:web:example.edu',
      name: 'Example University'
    },
    degree: {
      type: 'BachelorDegree',
      name: 'Bachelor of Science and Arts'
    }
  }
}
credential_json = JSON.generate(credential)
puts "  credential id: #{credential[:id]}"

puts
puts '== 2-of-3 issuer quorum threshold-signs the credential =='
two_shares = kg['shares'].first(2)
puts '  participating: registrar + academic_office'
sig = Confium::TC::Cmp20.sign(two_shares, 2, credential_json)

# Attach the proof per the W3C VC Data Model 2.0 spec.
verifiable_credential = credential.merge(
  proof: {
    type: 'ConfiumThresholdSignature2026',
    cryptosuite: 'ECDSA-P256-CMP20-2-of-3',
    created: '2026-07-31T00:00:00Z',
    verificationMethod: "#{issuer_did}#threshold-key-1",
    proofPurpose: 'assertionMethod',
    proofValue: Base64.strict_encode64(sig)
  }
)
puts "  proofValue: 0x#{sig.unpack1('H*')[0, 24]}... (#{sig.bytesize} bytes)"

File.write('/tmp/alumni-credential.json', JSON.generate(verifiable_credential))

puts
puts '== Verifier checks the credential =='
loaded = JSON.parse(File.read('/tmp/alumni-credential.json'))
proof = loaded['proof']

# Strip the proof, re-canonicalize (real implementations use
# JSON-LD canonicalization).
unsigned = loaded.except('proof')
unsigned_json = JSON.generate(unsigned)
loaded_sig = Base64.strict_decode64(proof['proofValue'])

# Verifier fetches the issuer's public key via DID resolution. Here
# we use the original public key directly.
require 'openssl'
asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(kg['public_key'])
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(loaded_sig[0, 32], 2)
s = OpenSSL::BN.new(loaded_sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(unsigned_json)

if pkey.dsa_verify_asn1(digest, der)
  puts "  ✓ credential verified — issued by #{loaded['issuer']} (2-of-3 quorum)"
  puts "  subject: #{loaded['credentialSubject']['id']}"
  puts "  degree:  #{loaded['credentialSubject']['degree']['name']}"
else
  abort '  ✗ credential FAILED'
end

puts
puts '== Anchor credential issuance to transparency log =='
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(unsigned_json + loaded_sig))
puts "  transparency root: 0x#{tree.root.unpack1('H*')[0, 24]}..."
puts
puts 'Done. The credential is issued by a 2-of-3 university quorum,'
puts "verifiable by any third party via the issuer's DID, and the"
puts 'issuance ceremony is anchored to a transparency log so the'
puts 'complete issuance history is auditable.'
puts
puts 'Real deployments would use a proper DID resolver (did:web,'
puts 'did:key, did:ion) and JSON-LD canonicalization; this example'
puts 'uses the simpler direct-key path for clarity.'
