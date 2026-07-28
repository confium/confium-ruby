#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Hello world: policy and FIPS mode.
# Run with: ruby examples/hello_policy.rb
#
# Demonstrates:
#   - Confium::Policy jurisdictional algorithm allow-lists
#   - FIPS 140 mode toggle
#   - Policy violation error handling

require "confium"

# Read current policy.
puts "FIPS mode: #{Confium::Policy.fips_mode}"
puts "Allowed algorithms: #{Confium::Policy.allowed_algorithms.inspect}"

# Set EU-style jurisdictional policy (P-384+).
Confium::Policy.configure do |p|
  p.allowed_algorithms = %w[ECDSA-P384 ECDSA-P521 Ed25519]
end
puts "\nEU policy set: #{Confium::Policy.allowed_algorithms.inspect}"

# Try to use a disallowed algorithm.
begin
  kp = Confium::Composite.generate_ed25519_keypair
  sig = Confium::Composite.sign_ed25519(kp["private_key"], "test")
  puts "Ed25519 signing: OK (allowed)"
rescue Confium::PolicyViolationError => e
  puts "Ed25519 signing: BLOCKED by policy"
  puts "  Details: #{e.details.inspect}"
end

# Toggle FIPS mode.
Confium::Policy.fips_mode = true
puts "\nFIPS mode enabled: #{Confium::Policy.fips_mode}"

# Reset for other examples.
Confium::Policy.fips_mode = false
Confium::Policy.allowed_algorithms = nil
puts "Policy reset to defaults."
