#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Code-signing use case: threshold-sign a software artifact (npm
# package tarball, gem, .deb, .jar — anything representable as bytes)
# using Confium's CMP20 threshold-ECDSA. Verify on the install side.
#
# Flow:
#
#   1. Issuance side (publisher CI):
#      - Publisher holds 2 of 3 threshold shares (e.g. release engineer,
#        security officer, CI bot — any 2 must participate).
#      - Sign the artifact hash; publish the signature alongside the
#        artifact.
#
#   2. Install side (consumer):
#      - Download the artifact + signature + publisher's public key.
#      - Verify the signature against the artifact hash.
#
# Why threshold signing for code signing?
#
#   - No single publisher key to lose. Two of three signers must
#     cooperate; a compromise of one key is survivable.
#   - Quorum policy enforced at signing time (release engineer +
#     security officer), not as an after-the-fact audit.
#   - Verifier-side cost is identical to a normal ECDSA-P256 verify —
#     no special tooling needed by installers.
#
# Run:
#   bundle exec ruby examples/code_signing.rb
#
# Then verify with OpenSSL:
#   openssl dgst -sha256 -verify <(ruby -e 'puts STDIN.read') \
#                -signature sig.bin artifact.bin
#
# (This example produces a raw 64-byte r||s signature; wrap into DER
# for tools that expect RFC 3279 encoding — see threshold_cmp20.rb
# for the DER wrapping pattern.)

require 'digest'
require 'json'
require 'tmpdir'
require 'confium'

# ----- Issuance side -----

# 1. Threshold keygen. In a real deployment each share is held by a
# different signer; here we use Confium's in-process DKG to keep the
# example self-contained.
puts '== Issuance: threshold keygen (2-of-3 CMP20) =='
kg = Confium::TC::Cmp20.keygen(2, 3)
puts "  joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  shares distributed to: release_engineer, security_officer, ci_bot'

# 2. Build the "artifact" — pretend it's an npm tarball.
artifact = 'imaginary-package-1.0.0.tgz contents...'
File.write('/tmp/artifact.bin', artifact)
artifact_hash = Digest::SHA256.digest(artifact)
puts "  artifact SHA-256: #{artifact_hash.unpack1('H*')[0, 24]}..."

# 3. Two of the three signers participate. They would normally be on
# different hosts; here we pass the share blobs directly.
two_shares = kg['shares'].first(2)
puts '  signing with shares [0, 1] (release_engineer + security_officer)'
# Sign the raw artifact — CMP20 internally hashes it for ECDSA's
# `z = H(m)` step. Signing the hash itself would double-hash.
sig = Confium::TC::Cmp20.sign(two_shares, 2, artifact)
File.binwrite('/tmp/artifact.sig', sig)
puts "  wrote /tmp/artifact.sig (#{sig.bytesize} bytes)"

# ----- Install side -----

puts
puts '== Install: verify the artifact =='
downloaded_artifact = File.read('/tmp/artifact.bin')
downloaded_sig = File.binread('/tmp/artifact.sig')
downloaded_pk = kg['public_key'] # in real life: from publisher's X.509 cert

# Verify under the joint public key using OpenSSL.
require 'openssl'
asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(downloaded_pk)
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)

r = OpenSSL::BN.new(downloaded_sig[0, 32], 2)
s = OpenSSL::BN.new(downloaded_sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der

digest = Digest::SHA256.digest(downloaded_artifact)
if pkey.dsa_verify_asn1(digest, der)
  puts "  ✓ artifact verified under publisher's threshold joint public key"
else
  abort '  ✗ verification FAILED — do not install'
end

# ----- Policy: anchor to transparency log -----

puts
puts '== Compliance: anchor signature to transparency log =='
tree = Confium::Transparency::MerkleTree.new
sig_hash = Digest::SHA256.digest(downloaded_sig)
seq = tree.append(sig_hash)
puts "  anchored at sequence #{seq}, current root: 0x#{tree.root.unpack1('H*')[0, 24]}..."
puts
puts 'Done. Anyone with the public key + signature can verify the artifact'
puts 'and the transparency log entry proves the publisher actually signed it.'
