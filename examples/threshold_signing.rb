#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Example: Shamir-split a P-256 secret across 5 parties, recover from
# any 3, and verify the recovered secret matches. Run with:
#   ruby examples/threshold_signing.rb

require "confium"

# Generate a P-256 signing keypair.
kp = Confium::TC::FrostP256.generate_keypair
puts "secret: 0x#{kp["private_key"].unpack1("H*")[0, 16]}..."

# Split into 5 shares, threshold = 3.
shares = Confium::TC::FrostP256.split_secret(kp["private_key"], 3, 5)
puts "split into #{shares.size} shares, threshold = 3"
shares.each { |s| puts "  share[#{s.x}]: 0x#{s.y_bytes.unpack1("H*")[0, 16]}..." }

# Recover from any 3 of the 5.
subset = [shares[0], shares[2], shares[4]]
recovered = Confium::TC::FrostP256.recover_secret(
  subset.map { |s| { "x" => s.x, "y" => s.y_bytes } }
)
puts "recovered from shares [0, 2, 4]: #{recovered == kp["private_key"] ? "MATCH" : "MISMATCH"}"

# Try with only 2 shares (insufficient — wrong answer, not an error).
subset2 = shares.first(2)
recovered2 = Confium::TC::FrostP256.recover_secret(
  subset2.map { |s| { "x" => s.x, "y" => s.y_bytes } }
)
puts "recovered from shares [0, 1]: #{recovered2 == kp["private_key"] ? "MATCH" : "WRONG (expected)"}"

# Sign a message with the original key.
sig = Confium::TC::FrostP256.sign(kp["private_key"], "threshold test")
puts "signature: der.size=#{sig["der"].size}, fixed.size=#{sig["fixed"].size}"
