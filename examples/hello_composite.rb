#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Hello world: composite signature verification.
# Run with: ruby examples/hello_composite.rb
#
# Demonstrates:
#   - Confium::Composite Ed25519 component signing
#   - Confium::Composite::Signature verification with per-component
#     result inspection
#   - Confium::Attributes predicate DSL
#

require 'confium'

# Generate a keypair and sign a message.
kp = Confium::Composite.generate_ed25519_keypair
message = 'hello composite signatures'
sig = Confium::Composite.sign_ed25519(kp['private_key'], message)

puts "Message: #{message}"
puts "Signature (Ed25519): #{sig['signature'].unpack1('H*')[0, 32]}..."

# Verify through the composite Signature object.
result = Confium::Composite::Signature.new([sig]).verify(message)
puts "Verification: #{result.all_verified? ? 'VALID' : 'INVALID'}"
result.per_component.each_value do |component|
  status = component['verified'] ? 'verified' : component['error']
  puts "  #{component['algorithm']}: #{status}"
end

# The wrong message fails verification (reported, not raised).
wrong = Confium::Composite::Signature.new([sig]).verify('tampered')
puts "Wrong message: #{wrong.all_verified? ? 'VALID' : 'INVALID'}"

# Demonstrate attribute predicates.
predicate = Confium::Attributes.parse(
  'and(min_count("role:director", 2), min_distinct("region", 2))'
)
puts "\nPredicate: 2-of-N directors from 2 distinct regions"

signer = lambda do |region|
  s = Confium::Attributes::Signer.new
  s.add('role:director', 'yes')
  s.add('region', region)
  s
end
directors = %w[na eu apac].map(&signer)

puts "2 signers, 2 regions: #{predicate.satisfied_by?(directors.first(2)) ? 'satisfied' : 'not satisfied'}"
puts "1 signer:            #{predicate.satisfied_by?(directors.first(1)) ? 'satisfied' : 'not satisfied'}"
