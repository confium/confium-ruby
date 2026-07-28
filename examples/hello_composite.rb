#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Hello world: composite signature verification.
# Run with: ruby examples/hello_composite.rb
#
# Demonstrates:
#   - Confium::Composite::Signature
#   - Built-in Ed25519 and ECDSA-P256 verifiers
#   - Per-component result inspection

require "confium"

# Generate a keypair and sign a message.
kp = Confium::Composite.generate_ed25519_keypair
message = "hello composite signatures"
sig = Confium::Composite.sign_ed25519(kp["private_key"], message)

puts "Message: #{message}"
puts "Signature (Ed25519): #{sig["signature"].unpack1("H*")[0, 32]}..."

# Verify using the built-in verifier.
result = Confium::Composite.verify_ed25519(kp["public_key"], message, sig["signature"])
puts "Verification: #{result ? "VALID" : "INVALID"}"

# Demonstrate attribute predicates.
predicate = Confium::Attributes::Predicate.parse(<<~DSL)
  2-of-3 directors
  from 2 distinct regions
DSL
puts "Predicate parsed: #{predicate}"

# Build a simple signer set.
signers = [
  OpenStruct.new(id: "d1", region: "na"),
  OpenStruct.new(id: "d2", region: "eu"),
  OpenStruct.new(id: "d3", region: "apac"),
]

satisfied = predicate.satisfied?(
  actors: signers.first(2),
  attributes: { region: signers.first(2).map(&:region) },
)
puts "2-of-3 from 2 regions: #{satisfied ? "satisfied" : "not satisfied"}"

satisfied2 = predicate.satisfied?(
  actors: signers,
  attributes: { region: signers.map(&:region) },
)
puts "3 signers from 3 regions: #{satisfied2 ? "satisfied" : "not satisfied"}"
