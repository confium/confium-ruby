# frozen_string_literal: true

require 'confium'

RSpec.describe 'Confium::TC::Cmp20 in-process threshold ECDSA' do
  def der_from_rs(raw_64)
    r = OpenSSL::BN.new(raw_64[0, 32], 2)
    s = OpenSSL::BN.new(raw_64[32, 32], 2)
    seq = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)])
    seq.to_der
  end

  def verify_p256(public_key_bytes, message, raw_64)
    require 'openssl'
    asn1 = OpenSSL::ASN1::Sequence([
                                     OpenSSL::ASN1::Sequence([
                                                               OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                               OpenSSL::ASN1::ObjectId('prime256v1')
                                                             ]),
                                     OpenSSL::ASN1::BitString(public_key_bytes)
                                   ])
    pkey = OpenSSL::PKey::EC.new(asn1.to_der)
    der = der_from_rs(raw_64)
    digest = OpenSSL::Digest::SHA256.digest(message)
    pkey.dsa_verify_asn1(digest, der)
  end

  it 'performs DKG and threshold sign with verify' do
    kg = Confium::TC::Cmp20.keygen(2, 3)
    expect(kg['shares'].length).to eq(3)
    expect(kg['public_key'].bytesize).to eq(33)

    msg = 'hello cmp20'
    sig = Confium::TC::Cmp20.sign(kg['shares'][0, 2], 2, msg)
    expect(sig.bytesize).to eq(64)

    expect(verify_p256(kg['public_key'], msg, sig)).to be true
  end

  it 'rejects signing with fewer shares than threshold' do
    kg = Confium::TC::Cmp20.keygen(3, 5)
    expect do
      Confium::TC::Cmp20.sign(kg['shares'][0, 2], 3, 'msg')
    end.to raise_error(Confium::ThresholdError)
  end

  it 'produces a 64-byte signature for full-committee signing' do
    kg = Confium::TC::Cmp20.keygen(3, 3)
    sig = Confium::TC::Cmp20.sign(kg['shares'], 3, 'msg')
    expect(sig.bytesize).to eq(64)
  end
end

RSpec.describe 'Confium::TC::Gg18 in-process threshold ECDSA' do
  def der_from_rs(raw_64)
    r = OpenSSL::BN.new(raw_64[0, 32], 2)
    s = OpenSSL::BN.new(raw_64[32, 32], 2)
    seq = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)])
    seq.to_der
  end

  def verify_p256(public_key_bytes, message, raw_64)
    require 'openssl'
    asn1 = OpenSSL::ASN1::Sequence([
                                     OpenSSL::ASN1::Sequence([
                                                               OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                               OpenSSL::ASN1::ObjectId('prime256v1')
                                                             ]),
                                     OpenSSL::ASN1::BitString(public_key_bytes)
                                   ])
    pkey = OpenSSL::PKey::EC.new(asn1.to_der)
    der = der_from_rs(raw_64)
    digest = OpenSSL::Digest::SHA256.digest(message)
    pkey.dsa_verify_asn1(digest, der)
  end

  it 'performs DKG and threshold sign with verify' do
    kg = Confium::TC::Gg18.keygen(2, 3)
    expect(kg['shares'].length).to eq(3)
    expect(kg['public_key'].bytesize).to eq(33)

    msg = 'hello gg18'
    sig = Confium::TC::Gg18.sign(kg['shares'][0, 2], 2, msg)
    expect(sig.bytesize).to eq(64)

    expect(verify_p256(kg['public_key'], msg, sig)).to be true
  end

  it 'rejects signing with fewer shares than threshold' do
    kg = Confium::TC::Gg18.keygen(3, 5)
    expect do
      Confium::TC::Gg18.sign(kg['shares'][0, 2], 3, 'msg')
    end.to raise_error(Confium::ThresholdError)
  end

  it 'produces a 64-byte signature for full-committee signing' do
    kg = Confium::TC::Gg18.keygen(3, 3)
    sig = Confium::TC::Gg18.sign(kg['shares'], 3, 'msg')
    expect(sig.bytesize).to eq(64)
  end
end
