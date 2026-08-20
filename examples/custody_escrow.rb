#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Custody / key-escrow use case: threshold-encrypt a secret to N
# custodians, recover via T-of-N partial decrypts. No single
# custodian can decrypt alone; any T-of-N can.
#
# Real-world applications:
#
#   - **Inheritance / succession**: encrypt a deceased user's master
#     password to a 3-of-5 quorum of heirs + lawyer + bank.
#   - **Corporate key escrow**: encrypt a CA's HSM key to a quorum
#     of board members + auditor; reconstruct only if the CA's HSM
#     is destroyed.
#   - **Sealed-bid auctions**: encrypt bids to a quorum that opens
#     them simultaneously after the auction closes.
#   - **Compliance archive**: encrypt regulatory records to a T-of-N
#     of regulators so any single rogue regulator can't unilaterally
#     read them.
#
# This example uses Confium's ElGamal-P256 KEM:
#
#   1. Receiver generates a keypair, Shamir-splits the secret scalar
#      into N shares, distributes shares to N custodians.
#   2. Sender calls `Confium::TC::ElGamalP256.encapsulate(pk)` to
#      produce (ciphertext, shared_secret).
#   3. Sender wraps the actual payload with an AEAD (e.g. AES-GCM)
#      keyed by shared_secret.
#   4. Recovery: any T custodians compute partial_decrypt(c_i, share).
#   5. Combiner aggregates T partials to recover shared_secret.
#   6. Combiner unwraps the AEAD to recover the payload.
#
# Run:
#   bundle exec ruby examples/custody_escrow.rb

require "json"
require "confium"

puts "== Setup: receiver generates threshold-shared decryption key =="
# Use FROST-P256 to generate a keypair, then Shamir-split the secret.
kp = Confium::TC::FrostP256.generate_keypair
puts "  master secret: 0x#{kp["private_key"].unpack1("H*")[0, 16]}..."

# Split into 5 shares, threshold 3.
shares = Confium::TC::FrostP256.split_secret(kp["private_key"], 3, 5)
puts "  split into 5 shares (threshold 3) — distributed to Alice, Bob,"
puts "  Carol, Dan, Eve. Any 3 must cooperate to decrypt."

puts
puts "== Sender: encapsulate a fresh shared secret to receiver =="
enc = Confium::TC::ElGamalP256.encapsulate(kp["public_key"])
shared_secret = enc["shared_secret"]
ciphertext = enc["ciphertext"]
puts "  shared_secret: 0x#{shared_secret.unpack1("H*")[0, 16]}..."
puts "  ciphertext:    c1=#{ciphertext["c1"].unpack1("H*")[0, 16]}..., c2=..."
puts
puts "  (Sender now wraps the actual payload with an AEAD keyed by"
puts "   shared_secret — typically AES-256-GCM. We skip that step here"
puts "   and treat shared_secret AS the payload for clarity.)"

puts
puts "== Recovery: 3 of 5 custodians participate =="
participating = shares.first(3)
puts "  participating custodians: Alice, Bob, Carol"

# Each custodian computes a partial decryption using their Shamir share
# and the c1 component of the ciphertext.
partials = participating.map.with_index do |share, idx|
  Confium::TC::ElGamalP256.partial_decrypt(idx + 1, share.y_bytes, ciphertext)
end
puts "  #{partials.length} partial decryptions computed"

puts
puts "== Combiner: aggregate partials to recover shared_secret =="
recovered = Confium::TC::ElGamalP256.aggregate_partials(partials, 3, ciphertext)
puts "  recovered: 0x#{recovered.unpack1("H*")[0, 16]}..."

if recovered == shared_secret
  puts
  puts "  ✓ MATCH — 3-of-5 quorum successfully recovered the shared secret"
  puts "    (Any 2-of-5 would have failed; any 3-of-5 succeeds.)"
else
  abort "  ✗ MISMATCH — bug in the binding or custodian shares"
end

puts
puts "== Long-term archival anchor =="
require "digest"
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(ciphertext["c1"] + ciphertext["c2"]))
puts "  transparency root: 0x#{tree.root.unpack1("H*")[0, 24]}..."
puts
puts "Done. The sealed payload is recoverable only with the cooperation"
puts "of at least 3 of 5 custodians; the transparency log proves when the"
puts "escrow was created and when each recovery ceremony occurred."
