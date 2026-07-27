#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Example: generate an Ed25519 keypair, sign a message as a composite
# signature, then verify it. Run with:
#   ruby examples/composite_verify.rb

require "confium"

# Generate a fresh Ed25519 keypair.
kp = Confium::Composite.generate_ed25519_keypair
puts "private key: 0x#{kp["private_key"].unpack1("H*")[0, 16]}..."
puts "public key:  0x#{kp["public_key"].unpack1("H*")[0, 16]}..."

# Sign a message.
message = "hello from confium"
component = Confium::Composite.sign_ed25519(kp["private_key"], message)
puts "signed '#{message}' with #{component["algorithm"]}"

# Build a composite signature from the single component.
sig = Confium::Composite::Signature.new([component])
puts "composite: #{sig.component_count} component(s), algorithms=#{sig.algorithms.inspect}"

# Verify.
result = sig.verify(message)
puts "verification: #{result.all_verified? ? "PASS" : "FAIL"}"
puts "per-component: #{result.per_component.inspect}"

# Verify wrong message.
bad = sig.verify("wrong message")
puts "wrong message: #{bad.all_verified? ? "PASS" : "FAIL"} (expected FAIL)"
