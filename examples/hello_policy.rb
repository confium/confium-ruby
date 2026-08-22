#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Hello world: policy and FIPS mode.
# Run with: ruby examples/hello_policy.rb
#
# Demonstrates:
#   - Confium::Policy jurisdictional algorithm/key-size rules
#   - FIPS 140 mode toggle
#   - Confium::PolicyViolationError details
#

require 'confium'

# Known jurisdictions and current state.
puts "Known jurisdictions: #{Confium::Policy.known_jurisdictions.inspect}"
puts "FIPS mode: #{Confium::Policy.fips_mode}"

# Set an EU-style jurisdictional policy (RSA >= 2048, ECDSA P-256+).
Confium::Policy.jurisdiction = :eu
puts "\nJurisdiction: #{Confium::Policy.jurisdiction}"

puts "RSA-3072 under EU policy: #{Confium::Policy.check!('rsa', key_bits: 3072) ? 'allowed' : 'blocked'}"

# A key below the policy minimum raises a typed PolicyViolationError.
begin
  Confium::Policy.check!('rsa', key_bits: 1024)
rescue Confium::PolicyViolationError => e
  puts 'RSA-1024 under EU policy: BLOCKED'
  puts "  Details: #{e.details.inspect}"
end

# FIPS mode: only FIPS-approved algorithms pass.
Confium::Policy.fips_mode = true
puts "\nFIPS mode: #{Confium::Policy.fips_mode}"
puts "ECDSA P-256 under FIPS: #{Confium::Policy.check!('ecdsa_p256', key_bits: 256) ? 'allowed' : 'blocked'}"
begin
  Confium::Policy.check!('ed25519', key_bits: 256)
rescue Confium::PolicyViolationError => e
  puts "Ed25519 under FIPS: BLOCKED (#{e.message})"
end

# Reset for other examples.
Confium::Policy.reset!
puts "\nPolicy reset: jurisdiction=#{Confium::Policy.jurisdiction.inspect}, fips=#{Confium::Policy.fips_mode}"
