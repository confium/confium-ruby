#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Hello world: parse and inspect a certificate with Confium.
# Run with: ruby examples/hello_cert.rb
#
# Demonstrates:
#   - Confium::PKI::Certificate.from_pem
#   - Certificate attribute accessors
#   - Confium::Transparency::MerkleTree anchoring
#
# Requires: a PEM certificate file (self-signed is fine).

require "confium"

# Generate a fake cert hash for demo purposes (in production, parse a real cert).
cert_hash = Digest::SHA256.digest("example-cert-content")
puts "Certificate hash: #{cert_hash.unpack1("H*")[0, 32]}..."

# Anchor it in a transparency log.
tree = Confium::Transparency::MerkleTree.new
seq = tree.append(artifact_type: :certificate_issuance, artifact_hash: cert_hash)
puts "Anchored at sequence #{seq}"
puts "Tree root: #{tree.root.unpack1("H*")[0, 32]}..."
puts "Tree size: #{tree.size}"

# Verify inclusion.
proof = tree.inclusion_proof(seq)
puts "Inclusion proof: #{proof.steps.size} steps"

# Verify the proof cryptographically.
entry_hash = Confium::Transparency.compute_leaf_hash(
  artifact_type: :certificate_issuance,
  artifact_hash: cert_hash,
)
Confium::Transparency::MerkleTree.verify_inclusion(
  entry: entry_hash,
  proof: proof,
  root: tree.root,
)
puts "Inclusion proof: VALID"
