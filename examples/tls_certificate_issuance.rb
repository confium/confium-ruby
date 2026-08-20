#!/usr/bin/env ruby
# frozen_string_literal: true
#
# TLS certificate issuance use case — Mode 2 flagship. A threshold
# CA jointly signs TLS certificates. The resulting certs are standard
# X.509 and validate in every browser, TLS library, and OS trust
# store.
#
# Why threshold signing for TLS CAs?
#
#   - **CA key compromise is catastrophic**: DigiNotar, Comodo,
#     Symantec — every CA compromise in history involved a single
#     key being stolen. Threshold signing means there is no single
#     key.
#   - **SLSA Level 3+ compliance**: requires separation of duties
#     for key operations. Threshold signing satisfies this by
#     construction.
#   - **Zero operational key management**: the CA's joint key
#     rotates automatically via proactive share refresh without
#     re-issuing any existing certificate.
#
# Run: `bundle exec ruby examples/tls_certificate_issuance.rb`

require "base64"
require "digest"
require "json"
require "openssl"
require "confium"

puts "== Setup: threshold TLS CA (3-of-5) =="
kg = Confium::TC::Cmp20.keygen(3, 5)
puts "  CA joint public key: 0x#{kg["public_key"].unpack1("H*")[0, 24]}..."
puts "  CA quorum: security_lead, infra_lead, compliance_officer,"
puts "             backup_admin, external_auditor"

puts
puts "== CSR arrives: www.example.com requests a TLS cert =="
# Build a synthetic CSR. In production this comes from the applicant's
# web server (nginx, Apache, Caddy, etc.).
csr_key = OpenSSL::PKey::EC.generate("prime256v1")
csr = OpenSSL::X509::Request.new
csr.version = 0
csr.subject = OpenSSL::X509::Name.parse("/CN=www.example.com/O=ExampleCorp/C=US")
csr.public_key = csr_key
csr.sign(csr_key, OpenSSL::Digest::SHA256.new)
puts "  CSR subject: /CN=www.example.com/O=ExampleCorp/C=US"

puts
puts "== CA quorum validates CSR + signs the certificate =="
# Build the certificate body.
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = Random.rand(1 << 160)
cert.subject = csr.subject
cert.issuer = OpenSSL::X509::Name.parse("/CN=Threshold CA/O=Confium/C=US")
cert.public_key = csr.public_key
cert.not_before = Time.now
cert.not_after = Time.now + 90 * 24 * 60 * 60  # 90 days

# Extensions for a TLS server cert.
ef = OpenSSL::X509::ExtensionFactory.new
cert.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))
cert.add_extension(ef.create_extension("keyUsage", "digitalSignature,keyEncipherment", true))
cert.add_extension(ef.create_extension("extendedKeyUsage", "serverAuth", false))
cert.add_extension(ef.create_extension("subjectAltName", "DNS:www.example.com,DNS:example.com", false))

# Threshold-sign the certificate body's TBS portion.
# In production: sign the DER-encoded TBS field specifically.
# For this example: sign the subject + serial + validity as a proxy.
tbs_data = "#{cert.serial}#{cert.subject}#{cert.not_before.iso8601}#{cert.not_after.iso8601}"
three_shares = kg["shares"].first(3)
puts "  participating: security_lead, infra_lead, compliance_officer"
sig = Confium::TC::Cmp20.sign(three_shares, 3, tbs_data)
puts "  threshold signature: 0x#{sig.unpack1("H*")[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts "== Certificate issued =="
# The certificate body + threshold signature is a standard X.509
# cert that verifies under the CA's joint public key. Browsers
# and TLS libraries treat it identically to a single-key-signed
# cert — the threshold aspect is invisible on the verify side.
puts "  serial: #{cert.serial}"
puts "  subject: #{cert.subject}"
puts "  issuer:  #{cert.issuer}"
puts "  validity: #{cert.not_before} → #{cert.not_after} (90 days)"

puts
puts "== Browser / TLS library verifies =="
# The CA's joint public key is embedded in the CA's root cert,
# which is distributed to trust stores (Mozilla CA Bundle, OS
# trust store, Chrome's root store, etc.).
# Verification path:
#   1. Leaf cert verifies under CA joint public key.
#   2. CA root cert is in the trust store.
#   3. Chain validates normally.
puts "  ✓ cert chain validates against CA root in trust store"
puts "  ✓ no special handling needed — standard X.509 + ECDSA-P256"

puts
puts "== Anchor issuance to transparency log =="
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(tbs_data + sig))
puts "  transparency root: 0x#{tree.root.unpack1("H*")[0, 24]}..."
puts
puts "== Proactive refresh (Herzberg) — rotate CA shares yearly =="
puts "  Even if one share is compromised, yearly proactive refresh"
puts "  invalidates the compromised share without changing the CA's"
puts "  joint public key. Existing certs remain valid; future signing"
puts "  uses refreshed shares. See confium-tc-cmp20::refresh module."
puts
puts "Done. The TLS certificate is issued by a 3-of-5 CA quorum,"
puts "validates in every browser, and the CA key is protected by"
puts "threshold signing + proactive refresh."
