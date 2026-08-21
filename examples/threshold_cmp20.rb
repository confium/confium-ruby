#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Example: CMP20 threshold-ECDSA ceremony. Generate a joint keypair
# across 3 parties (threshold 2), threshold-sign a message with any 2
# of the 3 shares, and verify the signature under the joint public key.
#
# Run with:
#   ruby examples/threshold_cmp20.rb

require 'confium'
require 'openssl'

# 1. DKG: produce 3 share blobs + joint public key.
kg = Confium::TC::Cmp20.keygen(2, 3)
puts 'dkg complete:'
puts "  shares:       #{kg['shares'].size} (#{kg['shares'].first.bytesize} bytes each)"
puts "  public_key:   0x#{kg['public_key'].unpack1('H*')[0, 16]}..."

# 2. Threshold sign with the first 2 shares (any 2 of 3 suffices).
message = 'threshold cmp20 signature'
signature = Confium::TC::Cmp20.sign(kg['shares'].first(2), 2, message)
puts 'signed with shares [0, 1]:'
puts "  message:      #{message.inspect}"
puts "  signature:    0x#{signature.unpack1('H*')[0, 16]}... (#{signature.bytesize} bytes)"

# 3. Verify under the joint public key using OpenSSL.
asn1 = OpenSSL::ASN1::Sequence([
                                 OpenSSL::ASN1::Sequence([
                                                           OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                           OpenSSL::ASN1::ObjectId('prime256v1')
                                                         ]),
                                 OpenSSL::ASN1::BitString(kg['public_key'])
                               ])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)

r = OpenSSL::BN.new(signature[0, 32], 2)
s = OpenSSL::BN.new(signature[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = OpenSSL::Digest::SHA256.digest(message)

if pkey.dsa_verify_asn1(digest, der)
  puts 'verify: OK (OpenSSL confirms under joint public key)'
else
  abort 'verify: FAIL'
end

# 4. Below-threshold attempt raises a typed error.
puts 'below-threshold attempt:'
begin
  Confium::TC::Cmp20.sign(kg['shares'].first(1), 2, message)
  abort 'should have raised'
rescue Confium::ThresholdError => e
  puts "  raised Confium::ThresholdError (have=#{e.have_count} need=#{e.need_count})"
end
