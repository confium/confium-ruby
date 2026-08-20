#!/usr/bin/env ruby
# frozen_string_literal: true
#
# SSH certificate signing use case — threshold-signed SSH user and
# host certificates. Drop-in replacement for `ssh-keygen -s` with
# single-key CA, but with multi-stakeholder threshold signing.
#
# Why threshold signing for SSH?
#
#   - **CA key compromise is catastrophic**: anyone with the SSH CA
#     key can impersonate any user / host in the org. Threshold
#     signing means no single party holds the CA key.
#   - **Compliance**: separation-of-duties frameworks (SOC 2, NIST
#     800-53) require "no single party can issue credentials alone".
#     Threshold signing satisfies this by construction.
#   - **Auditability**: every SSH cert issuance produces an audit
#     record in the transparency log.
#
# This example demonstrates signing the certificate body. In
# production, wrap the signature in the SSH certificate wire format
# per RFC 4252 / PROTOCOL.certkeys.

require "digest"
require "json"
require "tmpdir"
require "confium"

# An SSH user certificate body looks like (simplified):
#   string "ssh-rsa-cert-v01@openssh.com"
#   string nonce
#   mpint  e (RSA public exponent)
#   mpint  n (RSA modulus)
#   uint64 serial
#   uint32 type (1 = SSH_CERT_TYPE_USER)
#   string key id ("alice@example.com")
#   string valid principals ("alice", "ops")
#   ...
cert_body = {
  type: "ssh-rsa-cert-v01@openssh.com",
  serial: 12345,
  cert_type: :user,
  key_id: "alice@example.com",
  valid_principals: ["alice", "ops"],
  valid_after: Time.now.to_i - 60,
  valid_before: Time.now.to_i + 3600,
  critical_options: { source_address: "10.0.0.0/8" },
  extensions: { "permit-pty": true, "permit-X11-forwarding": false },
}
cert_json = JSON.generate(cert_body)

puts "== Setup: load SSH CA's threshold signing key =="
kg = Confium::TC::Cmp20.keygen(3, 5)
puts "  SSH CA joint public key: 0x#{kg["public_key"].unpack1("H*")[0, 24]}..."
puts "  CA shares held by: security_team_lead, it_director, compliance_officer,"
puts "                   backup_admin, auditor (3-of-5 quorum required)"

puts
puts "== User requests certificate (Alice needs SSH access) =="
puts "  user: alice@example.com"
puts "  principals: alice, ops"
puts "  valid: 1 hour"

puts
puts "== 3-of-5 CA quorum signs the certificate body =="
three_shares = kg["shares"].first(3)
puts "  participating: security_team_lead, it_director, compliance_officer"
sig = Confium::TC::Cmp20.sign(three_shares, 3, cert_json)
puts "  cert signature: 0x#{sig.unpack1("H*")[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts "== SSH client verifies against CA joint public key =="
# In production, the SSH client config (`~/.ssh/known_hosts` or
# `@cert-authority`) carries the CA's joint public key. Any
# threshold-signed cert verifies against it identically to a
# single-key-signed cert — there's nothing special about the
# threshold aspect on the verifier side.
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
digest = Digest::SHA256.digest(cert_json)

if pkey.dsa_verify_asn1(digest, der)
  puts "  ✓ certificate verified — Alice can SSH in"
else
  abort "  ✗ verification FAILED — access denied"
end

puts
puts "== Audit + transparency =="
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(cert_json + sig))
puts "  anchored to transparency root: 0x#{tree.root.unpack1("H*")[0, 24]}..."
puts
puts "Done. Alice's SSH certificate is signed by a 3-of-5 CA quorum."
puts "The CA's joint public key is the only thing the SSH clients need"
puts "to verify against — no special threshold handling required on"
puts "the verifier side."
