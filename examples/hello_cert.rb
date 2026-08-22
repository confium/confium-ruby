#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Hello world: anchor a certificate hash in a transparency log.
# Run with: ruby examples/hello_cert.rb
#
# Demonstrates:
#   - Confium::Transparency::MerkleTree append + root
#   - Inclusion proofs and their cryptographic verification
#

require 'digest'
require 'confium'

# Hash the artifact to anchor (in production, a real certificate).
cert_hash = Digest::SHA256.digest('example-cert-content')
puts "Certificate hash: #{cert_hash.unpack1('H*')[0, 32]}..."

# Anchor it in a transparency log.
tree = Confium::Transparency::MerkleTree.new
seq = tree.append(cert_hash)
puts "Anchored at sequence #{seq}"
puts "Tree root: #{tree.root.unpack1('H*')[0, 32]}..."
puts "Tree size: #{tree.size}"

# Prove inclusion against the root.
proof = tree.inclusion_proof(seq)
puts "Inclusion proof: #{proof.steps.size} steps"
puts "Inclusion proof: #{proof.verify(tree.root) ? 'VALID' : 'INVALID'}"
puts "Against a wrong root: #{proof.verify(Digest::SHA256.digest('other')) ? 'VALID' : 'INVALID'}"
