#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Hello world: typed error handling.
# Run with: ruby examples/hello_errors.rb
#
# Demonstrates:
#   - The typed Confium::Error hierarchy
#   - Per-error-class rescue patterns
#   - Structured .details accessor

require 'confium'

# Trigger a ParseError with bad input.
begin
  Confium::Transparency::MerkleTree.verify_inclusion(
    entry: 'not-bytes',
    proof: nil,
    root: "\x00" * 32
  )
rescue Confium::Error => e
  puts "Caught Confium::Error (#{e.class})"
  puts "  Message: #{e.message}"
  puts "  Details: #{e.details.inspect}"
end

# Demonstrate the full error hierarchy.
puts "\nError hierarchy:"
puts '  Confium::Error'
Confium::Error.descendants.sort_by(&:name).each do |klass|
  puts "  #{'  ' * (klass.ancestors.count - 1)}#{klass}"
end

# Demonstrate typed rescue for different error types.
[
  -> { Confium::Composite.verify_ed25519('bad', 'msg', 'bad') },
  -> { Confium::Transparency::MerkleTree.new.inclusion_proof(999) },
  -> { Confium::Attributes::Predicate.parse('invalid dsl !!!') }
].each_with_index do |op, i|
  op.call
rescue Confium::VerificationError => e
  puts "\n[#{i + 1}] VerificationError: #{e.message[0, 60]}"
rescue Confium::IndexError => e
  puts "\n[#{i + 1}] IndexError: #{e.message[0, 60]}"
rescue Confium::ParseError => e
  puts "\n[#{i + 1}] ParseError: #{e.message[0, 60]}"
rescue Confium::Error => e
  puts "\n[#{i + 1}] #{e.class}: #{e.message[0, 60]}"
end
