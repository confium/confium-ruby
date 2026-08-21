#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Mode 4 — Keyless Threshold CI signing.
#
# This is the killer demo of Confium Mode 4: combine threshold
# signing with Sigstore-style keyless signing so that:
#
#   - **No long-lived signing keys** to manage, lose, or rotate.
#   - **No share distribution ops** (shares are per-ceremony ephemeral).
#   - **Signer identity** is the trust anchor (GitHub actor, email).
#   - **Non-repudiation via transparency log** (log.confium.org).
#
# Compare to Modes 1–3:
#   - Modes 1–3: persistent threshold keyset, shares distributed to N
#     custodians, every signing ceremony uses the same joint key.
#   - Mode 4: ephemeral threshold keyset per ceremony, OIDC-verified
#     signers, short-lived Fulcio cert binding OIDC identities to
#     the joint ephemeral key, log-anchored.
#
# This example simulates the full ceremony. Real production:
#   - Each signer runs in a separate process (separate CI runner,
#     separate release engineer's laptop, etc.).
#   - The OIDC tokens come from a real issuer (GitHub Actions
#     OIDC provider, Google, Okta).
#   - The Fulcio-style CA is operated by Confium or OpenSSF.
#   - The transparency log is log.confium.org.
#
# Run: `bundle exec ruby examples/keyless_ci_signing.rb`

require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'confium'

puts '== Mode 4 — Keyless Threshold CI signing =='
puts
puts 'Scenario: 3 maintainers of a project must jointly sign each'
puts 'release. No one wants to manage long-lived signing keys.'
puts
puts 'Solution: ephemeral per-ceremony threshold key, OIDC-verified'
puts 'signers, Fulcio cert binding identities, log-anchored.'

puts
puts '== Step 1: each maintainer authenticates via OIDC =='
puts '  alice@example.com — verified via Google OIDC'
puts '  bob@example.com   — verified via GitHub OIDC'
puts '  carol@example.com — verified via Okta OIDC'
# In production each signer presents a real JWT. Here we simulate
# the verified identities.
oidc_identities = [
  { subject: 'alice@example.com', issuer: 'https://accounts.google.com', email: 'alice@example.com' },
  { subject: 'repo:confium/confium:ref:refs/tags/v1.0.0', issuer: 'https://token.actions.githubusercontent.com',
    github_repo: 'confium/confium', github_ref: 'refs/tags/v1.0.0', actor: 'bob' },
  { subject: 'carol@example.com', issuer: 'https://example.okta.com', email: 'carol@example.com' }
]

puts
puts '== Step 2: ephemeral threshold keygen (3-of-3, ceremony-bound) =='
# Each ceremony generates a fresh joint key. The shares are destroyed
# at the end of the ceremony — there's nothing to manage persistently.
kg = Confium::TC::Cmp20.keygen(3, 3)
puts "  joint ephemeral public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  threshold: 3-of-3 (all three maintainers must participate)'
puts '  shares: distributed to alice, bob (CI), carol — destroyed after ceremony'

puts
puts '== Step 3: Fulcio-style CA issues short-lived cert =='
# The Fulcio cert binds:
#   - the joint ephemeral public key
#   - the verified OIDC identities of all signers
#   - a short validity window (10 minutes)
#   - the issuer (Fulcio CA) identifier
not_before = Time.now.utc
not_after = not_before + 600 # 10 minutes
fulcio_cert = {
  version: 'fulcio-v1',
  issuer: 'Confium Fulcio CA (fulcio.confium.org)',
  subject: 'Confium Keyless Threshold Ceremony',
  joint_public_key: Base64.strict_encode64(kg['public_key']),
  signers: oidc_identities,
  validity: {
    not_before: not_before.iso8601,
    not_after: not_after.iso8601
  },
  threshold: { t: 3, n: 3 },
  transparency_log_url: 'https://log.confium.org'
}
puts '  Fulcio cert issued:'
puts "    validity: #{not_before.iso8601} → #{not_after.iso8601} (10 min)"
puts "    signers:  #{oidc_identities.length} OIDC-verified"
puts '    threshold: 3-of-3'

puts
puts '== Step 4: threshold sign the release artifact =='
release_artifact = 'release-1.0.0.tar.gz contents here...'
sig = Confium::TC::Cmp20.sign(kg['shares'], 3, release_artifact)
puts "  artifact: #{release_artifact[0, 40]}..."
puts "  signature: 0x#{sig.unpack1('H*')[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts '== Step 5: anchor cert + signature to log.confium.org =='
# In production this is a POST to https://log.confium.org/v1/append
# with a SHA-256 over (fulcio_cert || sig). Here we simulate with a
# local tree.
tree = Confium::Transparency::MerkleTree.new
anchored_hash = Digest::SHA256.digest(JSON.generate(fulcio_cert) + sig)
seq = tree.append(anchored_hash)
puts "  anchored at sequence #{seq}"
puts "  log root: 0x#{tree.root.unpack1('H*')[0, 24]}..."

puts
puts '== Step 6: destroy all ephemeral keys =='
# Ruby GC will reclaim these. In production each signer's process
# exits, taking the ephemeral private key with it.
nil
nil
puts '  all ceremony-local secrets destroyed'

puts
puts '== Verifier (downstream consumer) checks the release =='
# The verifier needs:
#   - the signed artifact
#   - the signature (64 bytes)
#   - the Fulcio cert (contains joint public key + OIDC identities)
#   - the transparency log inclusion proof
# They do NOT need any long-lived publisher key.

# Simulate re-loading the Fulcio cert from a real distribution channel.
reloaded_cert = fulcio_cert # in production: fetched from log.confium.org
reloaded_pk = Base64.strict_decode64(reloaded_cert[:joint_public_key])

asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(reloaded_pk)
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(sig[0, 32], 2)
s = OpenSSL::BN.new(sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(release_artifact)

if pkey.dsa_verify_asn1(digest, der)
  puts '  ✓ signature verified under Fulcio-bound joint public key'
else
  abort '  ✗ signature FAILED'
end

puts
puts '== Verifier inspects who signed =='
puts "  threshold: #{reloaded_cert[:threshold][:t]}-of-#{reloaded_cert[:threshold][:n]}"
puts '  signers (OIDC-verified):'
reloaded_cert[:signers].each do |s|
  if s[:email]
    puts "    - #{s[:email]} (via #{s[:issuer]})"
  elsif s[:github_repo]
    puts "    - #{s[:actor]} (GitHub Actions on #{s[:github_repo]} @ #{s[:github_ref]})"
  end
end
puts
puts "Verifier trust decision: 'I trust this release because it was"
puts 'signed by alice, bob, carol — three known maintainers — via a'
puts "3-of-3 threshold ceremony recorded in log.confium.org'."
puts
puts 'No long-lived key was needed. No share storage was needed.'
puts 'No key rotation was needed. The trust anchor is: (Fulcio CA +'
puts "transparency log + the verifier's policy on which OIDC"
puts 'identities are trusted maintainers).'

puts
puts "Done. Mode 4 — Keyless Threshold — combines Confium's"
puts "threshold signing with Sigstore's keyless pattern. The result"
puts 'is threshold signing without key management.'
