#!/usr/bin/env ruby
# frozen_string_literal: true
#
# DNSSEC zone signing use case — threshold-sign DNS zones. The zone
# signing key (ZSK) and key signing key (KSK) are threshold-shared
# across multiple DNS operators. No single operator can sign zone
# records alone.
#
# Why threshold signing for DNSSEC?
#
#   - **Operator key compromise**: if one DNS provider's signing
#     key is stolen, the attacker can forge DNS responses for every
#     domain under that provider. Threshold signing means there is
#     no single stealable key.
#   - **Multi-provider DNS**: large domains use multiple DNS
#     providers (Cloudflare + Route53 + NS1). Threshold signing
#     lets any T-of-N providers cooperate to sign zone updates
#     without any single provider holding the full key.
#   - **TLD / ccTLD operations**: country-code TLD operators must
#     follow strict key management procedures. Threshold signing
#     satisfies the "no single party" requirement by construction.
#
# Run: `bundle exec ruby examples/dnssec_signing.rb`

require "base64"
require "digest"
require "json"
require "openssl"
require "confium"

puts "== DNSSEC Zone Signing — Threshold Ceremony =="
puts
puts "Scenario: example.com is served by 3 DNS providers. Any 2 of"
puts "3 must cooperate to sign zone updates."

puts
puts "== Setup: DNSSEC zone signing quorum (2-of-3) =="
kg = Confium::TC::Cmp20.keygen(2, 3)
puts "  zone signing joint public key: 0x#{kg["public_key"].unpack1("H*")[0, 24]}..."
puts "  shares: cloudflare, route53, ns1"

puts
puts "== Zone update arrives =="
# Simulated DNS zone update. In production: RRSIG records per RRset.
zone_update = {
  zone: "example.com",
  serial: 2026073101,
  records: [
    { name: "example.com.", type: "A", ttl: 300, value: "93.184.216.34" },
    { name: "www.example.com.", type: "A", ttl: 300, value: "93.184.216.34" },
    { name: "api.example.com.", type: "A", ttl: 60, value: "93.184.216.35" },
    { name: "_dmarc.example.com.", type: "TXT", ttl: 3600, value: "v=DMARC1; p=reject;" },
  ],
  dnskey: {
    flags: 256,  # ZSK
    protocol: 3,
    algorithm: 13,  # ECDSAP256SHA256
    public_key: Base64.strict_encode64(kg["public_key"]),
  },
}
zone_json = JSON.generate(zone_update)
puts "  zone: #{zone_update[:zone]}"
puts "  serial: #{zone_update[:serial]}"
puts "  records: #{zone_update[:records].length}"

puts
puts "== 2-of-3 DNS provider quorum signs the zone update =="
two_shares = kg["shares"].first(2)
puts "  participating: cloudflare + route53"
sig = Confium::TC::Cmp20.sign(two_shares, 2, zone_json)
puts "  RRSIG (threshold): 0x#{sig.unpack1("H*")[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts "== Resolvers verify DNSSEC =="
loaded_pk = Base64.strict_decode64(zone_update[:dnskey][:public_key])

asn1 = OpenSSL::ASN1::Sequence([
  OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
    OpenSSL::ASN1::ObjectId("prime256v1"),
  ]),
  OpenSSL::ASN1::BitString(loaded_pk),
])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(sig[0, 32], 2)
s = OpenSSL::BN.new(sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(zone_json)

if pkey.dsa_verify_asn1(digest, der)
  puts "  ✓ zone signature verified — signed by 2-of-3 provider quorum"
  puts "  ✓ example.com. A 93.184.216.34 (TTL 300)"
  puts "  ✓ www.example.com. A 93.184.216.34 (TTL 300)"
  puts "  ✓ api.example.com. A 93.184.216.35 (TTL 60)"
else
  abort "  ✗ zone signature FAILED — DNS responses untrusted"
end

puts
puts "== Anchor zone update to transparency log =="
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(zone_json.dup.force_encoding("BINARY") + sig))
puts "  transparency root: 0x#{tree.root.unpack1("H*")[0, 24]}..."
puts
puts "Done. The DNS zone is signed by a 2-of-3 provider quorum."
puts "No single DNS provider can forge zone records; resolvers"
puts "verify DNSSEC normally; the update is anchored to a transparency"
puts "log for complete audit history of zone changes."
