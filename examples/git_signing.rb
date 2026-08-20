#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Git commit signing use case — threshold-sign git commits and tags.
# Drop-in replacement for `git commit -S` with GPG, but with
# multi-stakeholder threshold signing instead of single-key.
#
# Why threshold signing for git?
#
#   - **Release integrity**: 2-of-3 maintainers must cooperate to
#     sign a release tag. No single maintainer can ship a backdoor.
#   - **Supply-chain hardening**: every commit on a protected branch
#     is threshold-signed; unsigned commits are rejected at push time.
#   - **Verifiable history**: third parties verify commits under the
#     project's joint public key, which is published in the README.
#
# This example demonstrates the signature production; git's
# gpgsig-format wrapper would be added in production via a small
# `git-cat-file --filters` hook.

require "base64"
require "digest"
require "json"
require "tmpdir"
require "confium"

# In real git signing, the "commit object" git signs is the canonical
# commit text: `tree <sha>\nparent <sha>\nauthor ...\ncommitter ...\n\n<message>\n`.
# Here we use a synthetic commit object for the demo.
commit_object = <<~COMMIT
  tree 3f8a2b1c5d4e6f7a8b9c0d1e2f3a4b5c6d7e8f9a
  parent a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
  author Alice <alice@example.com> 1722400000 +0000
  committer Alice <alice@example.com> 1722400000 +0000

  Release v2.0.0 — security patches
COMMIT

puts "== Setup: load project's threshold signing key =="
kg = Confium::TC::Cmp20.keygen(2, 3)
puts "  project joint public key: 0x#{kg["public_key"].unpack1("H*")[0, 24]}..."
puts "  shares held by: lead_maintainer, security_officer, release_manager"

puts
puts "== Two maintainers threshold-sign the commit =="
two_shares = kg["shares"].first(2)
sig = Confium::TC::Cmp20.sign(two_shares, 2, commit_object)
puts "  commit signature: 0x#{sig.unpack1("H*")[0, 24]}... (#{sig.bytesize} bytes)"

# Wrap the raw (r||s) signature in the gpgsig format git uses:
#
#   gpgsig -----BEGIN PGP SIGNATURE-----
#             <base64 signature>
#             -----END PGP SIGNATURE-----
#
# In production, use a PGP signature wrapper (RFC 4880) — Confium's
# raw ECDSA needs the wrapper to be git-compatible. The wrapper is
# ~30 lines of code; see https://git-scm.com/docs/gitformat-signature
# for the canonical format.
puts
puts "== Wrap in git gpgsig format =="
gpgsig = "-----BEGIN CONFIMUM SIGNATURE-----\n" \
         "Version: Confium 0.3 CMP20-ECDSA-P256 2-of-3\n\n" \
         "#{Base64.strict_encode64(sig)}\n" \
         "-----END CONFIMUM SIGNATURE-----\n"
puts gpgsig.lines.first(2).join

puts
puts "== Verify (downstream consumer) =="
require "openssl"
asn1 = OpenSSL::ASN1::Sequence([
  OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
    OpenSSL::ASN1::ObjectId("prime256v1"),
  ]),
  OpenSSL::ASN1::BitString(kg["public_key"]),
])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(sig[0, 32], 2)
s = OpenSSL::BN.new(sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(commit_object)

if pkey.dsa_verify_asn1(digest, der)
  puts "  ✓ commit verified under project's joint public key"
else
  abort "  ✗ verification FAILED"
end

puts
puts "== Anchor to transparency log =="
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(commit_object.dup.force_encoding("BINARY") + sig))
puts "  transparency root: 0x#{tree.root.unpack1("H*")[0, 24]}..."
puts
puts "Done. The commit is signed by 2-of-3 maintainers; downstream"
puts "consumers verify under the project's published joint key."
