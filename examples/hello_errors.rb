#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Hello world: typed error handling.
# Run with: ruby examples/hello_errors.rb
#
# Demonstrates:
#   - The typed Confium::Error hierarchy raised from the native
#     extension (Confium::ThresholdError with structured details)
#   - The .details accessor on typed errors
#   - Typed parse errors from native validation paths
#

require 'confium'

# A threshold operation below its threshold raises a typed error with
# structured context carried across the FFI boundary.
kg = Confium::TC::Cmp20.keygen(3, 5)
begin
  Confium::TC::Cmp20.sign(kg['shares'].first(2), 3, 'msg')
rescue Confium::ThresholdError => e
  puts "Caught #{e.class}: #{e.message}"
  puts "  have_count: #{e.have_count}, need_count: #{e.need_count}"
  puts "  Details: #{e.details.inspect}"
end

# Demonstrate the full error hierarchy. Eager-load the subclasses so
# Class#subclasses can see them (they are otherwise autoloaded on
# first reference).
%w[parse_error validation_error verification_error threshold_error crypto_error
   not_found_error index_error unresolved_signer_error policy_violation_error].each do |f|
  require "confium/errors/#{f}"
end
def print_hierarchy(klass, indent = 0)
  puts "#{'  ' * indent}#{klass}"
  klass.subclasses.sort_by(&:name).each { |c| print_hierarchy(c, indent + 1) }
end
puts "\nError hierarchy:"
print_hierarchy(Confium::Error)

# Native validation failures raise typed errors too — ParseError for
# malformed input, ArgumentError for bad argument shapes.
[
  -> { Confium::Attributes.parse('not_a_function(') },
  -> { Confium::Config::Manifest.from_toml('not = = toml') },
  -> { Confium::Composite.sign_ed25519('x' * 16, 'msg') }
].each_with_index do |op, i|
  op.call
rescue Confium::Error => e
  puts "\n[#{i + 1}] #{e.class}: #{e.message[0, 60]}"
  puts "      details: #{e.details.inspect}"
rescue StandardError => e
  puts "\n[#{i + 1}] #{e.class}: #{e.message[0, 60]}"
end
