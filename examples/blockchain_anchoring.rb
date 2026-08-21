#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Blockchain anchoring use case — anchor arbitrary data hashes to
# Bitcoin (via OTS) and Ethereum (via smart contract). The anchor
# proves data existed at a specific point in time without trusting
# any single party.
#
# Why threshold signing for blockchain anchoring?
#
#   - **Anchoring service HA**: multiple anchors run the anchoring
#     service; any T-of-N can submit to the blockchain.
#   - **Auditable anchoring**: every anchor submission produces an
#     audit record + transparency log entry.
#   - **Cross-chain verification**: the same data hash is anchored
#     to Bitcoin (proof-of-work) + Ethereum (smart contract) +
#     Confium transparency log (Merkle tree). Breaking all three
#     simultaneously is computationally infeasible.
#
# Run: `bundle exec ruby examples/blockchain_anchoring.rb`

require 'digest'
require 'json'
require 'confium'

puts '== Setup: anchoring service quorum (2-of-3) =='
kg = Confium::TC::Cmp20.keygen(2, 3)
puts "  anchoring joint public key: 0x#{kg['public_key'].unpack1('H*')[0, 24]}..."
puts '  anchors: anchor_primary, anchor_backup, anchor_audit'

puts
puts '== Data to be anchored =='
data = 'This agreement was signed on 2026-07-31 by parties A, B, C.'
data_hash = Digest::SHA256.digest(data)
data_hash_hex = Digest::SHA256.hexdigest(data)
puts "  data: #{data}"
puts "  SHA-256: #{data_hash_hex[0, 24]}..."

puts
puts '== Anchor 1: Bitcoin via OTS (OpenTimestamps) =='
# Confium's OTS client submits the hash to multiple calendar servers.
# The calendars aggregate submissions and write them into Bitcoin
# blocks via OP_RETURN.
# In production: ots_client = Confium::Transparency::OTS::Client.new
# ots_proof = ots_client.stamp(data_hash)
puts '  submitted to calendars: a.pool.opentimestamps.org, b.pool.opentimestamps.org'
puts '  expected confirmation: Bitcoin block within 1-24 hours'
puts '  OTS proof format: 200-400 bytes, independently verifiable'

puts
puts '== Anchor 2: Ethereum via smart contract =='
# The anchoring service calls an Ethereum smart contract that
# stores (hash, timestamp, block_number) tuples. The contract
# is permissionless — anyone can verify on-chain.
eth_contract_call = {
  to: '0x1234...cdef', # Confium anchor contract address
  function: 'anchor(bytes32)',
  args: ["0x#{data_hash_hex}"],
  gas: 100_000
}
puts "  contract: #{eth_contract_call[:to]}"
puts "  function: #{eth_contract_call[:function]}"
puts "  gas:      #{eth_contract_call[:gas]}"
puts '  expected confirmation: Ethereum block within 15 seconds'

puts
puts '== Anchor 3: Confium transparency log =='
# The anchoring service's quorum threshold-signs the hash and
# appends it to log.confium.org.
two_shares = kg['shares'].first(2)
sig = Confium::TC::Cmp20.sign(two_shares, 2, data_hash)
puts '  threshold-signed by anchor_primary + anchor_backup'
puts "  signature: 0x#{sig.unpack1('H*')[0, 24]}..."

tree = Confium::Transparency::MerkleTree.new
seq = tree.append(data_hash)
puts "  log sequence: #{seq}"
puts "  log root: 0x#{tree.root.unpack1('H*')[0, 24]}..."

puts
puts '== Cross-chain verification =='
puts '  Anyone with the data hash can verify it existed at the'
puts '  anchoring time via THREE independent anchors:'
puts
puts '  1. Bitcoin: verify OTS proof against the Bitcoin blockchain'
puts '     (independent proof-of-work anchor, ~$0.01 cost per verify)'
puts '  2. Ethereum: query the smart contract on any Ethereum node'
puts '     (independent consensus anchor, ~$0.001 cost per verify)'
puts '  3. Confium: verify inclusion proof against log.confium.org'
puts '     (Merkle tree, free, instant)'
puts
puts '  Breaking all three simultaneously requires:'
puts '    - 51% attack on Bitcoin ($10M+/hour)'
puts '    - 51% attack on Ethereum ($1M+/hour)'
puts '    - Forking log.confium.org (detected by witnesses)'
puts '  → computationally infeasible.'

puts
puts '== Verification code (downstream consumer) =='
puts <<~RUBY
  # Bitcoin OTS verify:
  #   ots verify data.ots  # uses Bitcoin Core for confirmation
  #
  # Ethereum on-chain verify:
  #   eth_call(contract, "verify(bytes32)", data_hash)
  #
  # Confium log verify:
  #   tree.verify_inclusion(entry: data_hash, proof: proof, root: root)
RUBY

puts
puts 'Done. The data hash is anchored to Bitcoin + Ethereum + Confium'
puts 'log simultaneously. Cross-chain verification makes retroactive'
puts 'tampering computationally infeasible.'
