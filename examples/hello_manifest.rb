#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Hello world: deployment manifest.
# Run with: ruby examples/hello_manifest.rb
#
# Demonstrates:
#   - Confium::Config::Manifest parsing from TOML
#   - Inspecting deployment, tiers, and quorums
#   - Manifest validation
#

require 'confium'

manifest = Confium::Config::Manifest.from_toml(<<~TOML)
  [deployment]
  name = "CNML Pilot Deployment"
  operator = "BIML"
  manifest_version = 1

  [[tiers]]
  name = "Manufacturer"
  role = "manufacturer"
  signing_algorithm = "Ed25519"
  threshold = { t = 3, n = 5 }

  [[tiers]]
  name = "BIML Directors"
  role = "biml_director"
  signing_algorithm = "Ed25519"
  threshold = { t = 5, n = 9 }

  [[quorums]]
  name = "Manufacturers"
  coordinator = "coord-001"
  threshold = { t = 3, n = 5 }
TOML

puts "Deployment:   #{manifest.deployment_name}"
puts "Operator:     #{manifest.operator}"
puts "Version:      #{manifest.manifest_version}"
puts "Tiers:        #{manifest.tier_count}"
manifest.tier_count.times do |i|
  puts "  tier #{i}: #{manifest.tier_name_at(i)}"
end
puts "Quorums:      #{manifest.quorum_count}"

# Validate the manifest (schema + semantic checks).
puts "\nValid manifest: #{manifest.valid? ? 'yes' : 'no'}"
puts manifest.validate unless manifest.valid?

# An unsupported version is flagged by validation.
bad = Confium::Config::Manifest.from_toml(<<~TOML)
  [deployment]
  name = "Bad"
  operator = "Nobody"
  manifest_version = 99
TOML
puts "Bad version flagged: #{bad.validate.first}"
