#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Container image signing use case — threshold-sign OCI container
# image manifests (sigstore-cosign alternative). The signature
# attaches as an annotation on the image's signature object.
#
# Why threshold signing for containers?
#
#   - **Supply-chain security**: a single compromised registry key
#     can ship backdoored images to every deployment. Threshold
#     signing forces a quorum before any image is trusted.
#   - **CI integration**: the CI bot holds one share; the security
#     team holds another. No single party can sign an image alone.
#   - **Drop-in for cosign**: the signature is a standard P-256
#     ECDSA signature over the manifest digest. Existing policy
#     controllers (Kyverno, OPA Gatekeeper) can verify it with a
#     one-line policy change.
#
# Run:
#   bundle exec ruby examples/container_signing.rb
#
# Production: store the signature in a separate OCI artifact (like
# cosign does) and configure your admission controller to require
# a verified signature before pod creation.

require 'base64'
require 'digest'
require 'json'
require 'open3'
require 'tmpdir'
require 'confium'

# In a real deployment, the manifest comes from `docker manifest inspect
# myimage:latest`. Here we use a synthetic manifest for the demo.
manifest = {
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  config: {
    mediaType: 'application/vnd.oci.image.config.v1+json',
    digest: "sha256:#{Digest::SHA256.hexdigest('imaginary-config')}",
    size: 18
  },
  layers: []
}
manifest_json = JSON.generate(manifest)
manifest_digest = "sha256:#{Digest::SHA256.hexdigest(manifest_json)}"

puts "== Setup: load publisher's threshold signing key =="
kg = Confium::TC::Cmp20.keygen(2, 3)
puts "  publisher joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  shares held by: ci_bot, release_engineer, security_officer'

puts
puts '== CI: build + push image =='
puts '  image: registry.example.com/app:1.0.0'
puts "  manifest digest: #{manifest_digest}"

puts
puts '== CI + release_engineer: 2-of-3 threshold sign the manifest =='
two_shares = kg['shares'].first(2)
sig = Confium::TC::Cmp20.sign(two_shares, 2, manifest_json)
puts "  signature: 0x#{sig.unpack1('H*')[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts '== Push signature as OCI artifact (cosign-style) =='
signature_artifact = {
  schemaVersion: 2,
  mediaType: 'application/vnd.oci.image.manifest.v1+json',
  config: {
    mediaType: 'application/vnd.dev.cosign.simplesigning.v1+json',
    digest: "sha256:#{Digest::SHA256.hexdigest(manifest_json)}",
    size: manifest_json.bytesize
  },
  annotations: {
    'dev.cosignproject.cosign/signature' => Base64.strict_encode64(sig),
    'dev.confium.threshold/scheme' => 'CMP20-ECDSA-P256',
    'dev.confium.threshold/quorum' => '2-of-3'
  },
  layers: []
}
puts '  signature artifact pushed to:'
puts "    registry.example.com/app:sha256-#{manifest_digest.sub('sha256:', '')}.sig"

puts
puts '== Kubernetes admission controller: verify at deploy time =='
# Simulate what a Kyverno / OPA Gatekeeper policy would do.
downloaded_sig = Base64.strict_decode64(signature_artifact[:annotations]['dev.cosignproject.cosign/signature'])
Digest::SHA256.hexdigest(manifest_json)

require 'openssl'
asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(kg['public_key'])
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(downloaded_sig[0, 32], 2)
s = OpenSSL::BN.new(downloaded_sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(manifest_json)

if pkey.dsa_verify_asn1(digest, der)
  puts "  ✓ admission allowed — manifest signature verified under publisher's joint key"
else
  puts '  ✗ admission denied — signature verification failed'
end

puts
puts '== Transparency log anchor =='
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(sig + manifest_json))
puts "  anchored to transparency root: 0x#{tree.root.unpack1('H*')[0, 24]}..."
puts
puts 'Done. The image is signed by a 2-of-3 quorum, the signature is'
puts 'stored as an OCI artifact alongside the image, and the signing'
puts 'ceremony is anchored to a transparency log for audit.'
