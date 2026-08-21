#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Hello world: deployment manifest.
# Run with: ruby examples/hello_manifest.rb
#
# Demonstrates:
#   - Confium::Config::Manifest loading from TOML
#   - Inspecting signers, quorum, policy
#   - Validating a deployment configuration

require 'confium'

# Create a sample manifest TOML.
toml = <<~TOML
  [coordinator]
  bind = "0.0.0.0:7443"
  transport = "quic"

  [quorum]
  threshold = 3
  total = 5

  [policy]
  fips_mode = false
  allowed_signature_algorithms = ["ECDSA-P256", "Ed25519"]
  allowed_hash_algorithms = ["SHA-256", "SHA-384"]

  [[signers]]
  id = "director-1"
  endpoint = "director-1.internal:7500"
  attributes = { region = "na", role = "director" }

  [[signers]]
  id = "director-2"
  endpoint = "director-2.internal:7500"
  attributes = { region = "eu", role = "director" }
TOML

# Write to temp file.
path = '/tmp/confium-hello-manifest.toml'
File.write(path, toml)

# Load and inspect.
manifest = Confium::Config::Manifest.from_file(path)
puts "Manifest loaded from #{path}"
puts "Coordinator bind: #{manifest.coordinator_bind}"
puts "Transport: #{manifest.transport}"
puts "Quorum: #{manifest.quorum[:threshold]}-of-#{manifest.quorum[:total]}"
puts "FIPS mode: #{manifest.fips_mode}"
puts "Allowed algorithms: #{manifest.allowed_algorithms.inspect}"
puts "Signers: #{manifest.signers.size}"
manifest.signers.each do |signer|
  puts "  #{signer[:id]} @ #{signer[:endpoint]} (#{signer[:attributes].inspect})"
end

# Clean up.
File.delete(path)
puts "\nDone. Manifest validated successfully."
