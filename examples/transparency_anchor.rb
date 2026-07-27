#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Example: anchor a string in a Merkle transparency tree and verify
# the inclusion proof. Run with:
#   ruby examples/transparency_anchor.rb

require "confium"
require "digest"

tree = Confium::Transparency::MerkleTree.new

# Anchor three "artifacts" (in practice these would be certificate DER bytes).
artifacts = ["hello", "world", "confium"]
artifacts.each do |a|
  hash = Digest::SHA256.digest(a)
  seq = tree.append(hash)
  puts "anchored '#{a}' at sequence #{seq}"
end

puts "root: 0x#{tree.root.unpack1("H*")}"

# Verify inclusion for each artifact.
artifacts.each_with_index do |a, i|
  hash = Digest::SHA256.digest(a)
  proof = tree.inclusion_proof(i)
  puts "proof[#{i}]: seq=#{proof.sequence}, steps=#{proof.steps.size}, verify=#{proof.verify(tree.root)}"
end

# Iterate via to_a.
puts "all sequences: #{tree.to_a.map(&:sequence).inspect}"
