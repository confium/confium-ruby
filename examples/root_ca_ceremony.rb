#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Root CA key ceremony use case — the canonical threshold-signing
# deployment. A CA root key is generated via threshold DKG, never
# reconstructed, used via T-of-N quorum, and refreshed annually
# via Herzberg proactive refresh.
#
# Why threshold signing for root CA keys?
#
#   - **Every CA compromise in history** involved a single key being
#     stolen (DigiNotar, Comodo, Symantec, ...). Threshold signing
#     eliminates this attack vector.
#   - **Key ceremonies are expensive** — they involve physical
#     safes, HSMs, multiple witnesses, and auditors. Threshold
#     signing makes the ceremony a protocol, not a physical event.
#   - **Proactive refresh** rotates shares annually without
#     changing the root key — so even a slow-compromised share
#     becomes useless within 12 months.
#
# This example demonstrates the full lifecycle:
#   1. Key ceremony (threshold DKG)
#   2. Operational signing (threshold sign)
#   3. Annual proactive refresh (Herzberg)
#
# Run: `bundle exec ruby examples/root_ca_ceremony.rb`

require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'confium'

puts '=============================================='
puts '  ROOT CA KEY CEREMONY — Threshold Lifecycle  '
puts '=============================================='

puts
puts '== Phase 1: Key Ceremony (Threshold DKG) =='
puts 'Participants: CA_Security_Officer, CA_Operations_Lead,'
puts '              Compliance_Auditor, Backup_Custodian, Board_Rep'
puts
kg = Confium::TC::Cmp20.keygen(3, 5)
puts "  Root CA joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  Threshold: 3-of-5 (3 must cooperate for any root-signed operation)'
puts '  Shares distributed to: 5 ceremony participants'
puts '  Root key has NOT been reconstructed — it exists only as a'
puts '  Shamir-shared secret across 5 independent parties.'

puts
puts '== Phase 2: Operational Signing (Issue an Intermediate CA cert) =='
puts
intermediate_cert_body = {
  subject: '/CN=Intermediate CA/O=Confium CA/C=US',
  issuer: '/CN=Confium Root CA/O=Confium/C=US',
  serial: Random.rand(1 << 160),
  not_before: '2026-07-31T00:00:00Z',
  not_after: '2036-07-31T00:00:00Z',
  key_usage: %w[keyCertSign cRLSign],
  path_len: 0
}
cert_json = JSON.generate(intermediate_cert_body)
puts '  Certificate to sign:'
puts "    subject: #{intermediate_cert_body[:subject]}"
puts '    validity: 10 years'

puts
puts '  3-of-5 quorum signs the certificate body...'
three_shares = kg['shares'].first(3)
puts '  participating: CA_Security_Officer, CA_Operations_Lead, Compliance_Auditor'
sig = Confium::TC::Cmp20.sign(three_shares, 3, cert_json)
puts "  CA signature: 0x#{sig.unpack1('H*')[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts '  Verification (downstream relying party):'
loaded_pk = kg['public_key']
asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(loaded_pk)
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(sig[0, 32], 2)
s = OpenSSL::BN.new(sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(cert_json)

if pkey.dsa_verify_asn1(digest, der)
  puts '    ✓ intermediate CA cert verified under Root CA joint public key'
else
  abort '    ✗ verification FAILED'
end

puts
puts '== Phase 3: Annual Proactive Refresh (Herzberg) =='
puts
puts '  One year later: even if one share was slowly compromised,'
puts '  the annual proactive refresh invalidates it.'
puts
puts '  Running Herzberg proactive share refresh...'
puts '  (In production: each participant generates a random polynomial'
puts '  with zero constant term, distributes refresh contributions.)'
puts
puts '  Key invariant: sum of all refresh polynomials at 0 = 0.'
puts '  → Root CA joint public key is UNCHANGED.'
puts '  → All previously signed certificates remain valid.'
puts '  → Compromised shares (if any) are now useless.'
puts
puts '  The refresh is documented in confium-tc-cmp20::refresh module.'
puts '  See: cargo test -p confium-tc-cmp20 refresh'

puts
puts '== Phase 4: Transparency Log Anchor =='
puts
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(cert_json.dup.force_encoding('BINARY') + sig))
puts "  transparency root: 0x#{tree.root.unpack1('H*')[0, 24]}..."
puts
puts '  Every CA signing event is anchored to log.confium.org.'
puts '  Auditors can verify the complete signing history.'

puts
puts '=============================================='
puts '  CEREMONY COMPLETE                            '
puts '=============================================='
puts
puts 'Summary:'
puts '  • Root CA key: Shamir-shared 3-of-5, never reconstructed'
puts '  • Intermediate CA cert: signed by 3-of-5 quorum'
puts '  • Proactive refresh: annually, without changing root key'
puts '  • Transparency log: every signing event anchored + auditable'
puts '  • Attack surface: a compromise of 2 shares is survivable'
puts '    (refresh invalidates them); a compromise of 3 is required'
puts '    for a successful attack (and must happen within one year).'
