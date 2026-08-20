#!/usr/bin/env ruby
# Cross-binding parity fixture generator (Ruby side).
#
# Produces a JSON file at the path given by ARGV[0] containing:
#   {
#     "scheme": "CMP20" | "GG18",
#     "public_key": "<hex>",
#     "message": "<hex>",
#     "signature": "<hex>"
#   }
#
# The Python companion (`scripts/parity_verify.py`) loads this fixture
# and verifies the signature under the public key. This proves the wire
# format is identical across bindings — a Ruby-produced signature must
# verify in Python and vice versa.

require "json"
require "confium"

scheme = ENV.fetch("SCHEME", "CMP20")
threshold = Integer(ENV.fetch("THRESHOLD", "2"))
party_count = Integer(ENV.fetch("PARTY_COUNT", "3"))
message = ENV.fetch("MESSAGE", "cross-binding parity")
out_path = ARGV.fetch(0)

kg =
  case scheme
  when "CMP20" then Confium::TC::Cmp20.keygen(threshold, party_count)
  when "GG18"  then Confium::TC::Gg18.keygen(threshold, party_count)
  else raise "unknown scheme: #{scheme}"
  end

mod =
  case scheme
  when "CMP20" then Confium::TC::Cmp20
  when "GG18"  then Confium::TC::Gg18
  end

signature = mod.sign(kg["shares"].first(threshold), threshold, message)

fixture = {
  "scheme" => scheme,
  "threshold" => threshold,
  "party_count" => party_count,
  "public_key" => kg["public_key"].unpack1("H*"),
  "message" => message.bytes.pack("C*").unpack1("H*"),
  "signature" => signature.unpack1("H*"),
}

File.write(out_path, JSON.generate(fixture))
$stderr.puts "ruby: wrote #{scheme} fixture to #{out_path}"
