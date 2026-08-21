# frozen_string_literal: true

require 'tmpdir'
require 'confium'

RSpec.describe Confium::TC::ShareFile do
  let(:kg) { Confium::TC::Cmp20.keygen(2, 3) }

  it 'round-trips through save / load' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'shares.json')
      sf = described_class.from_keygen('CMP20-ECDSA-P256', kg)
      sf.save(path)

      loaded = described_class.load(path)
      expect(loaded.scheme).to eq('CMP20-ECDSA-P256')
      expect(loaded.party_count).to eq(3)
      expect(loaded.public_key).to eq(kg['public_key'])
      expect(loaded.shares).to eq(kg['shares'])
    end
  end

  it 'creates parent directories on save' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'nested', 'deep', 'shares.json')
      sf = described_class.from_keygen('CMP20-ECDSA-P256', kg)
      sf.save(path)
      expect(File.exist?(path)).to be(true)
    end
  end

  it 'shares loaded from disk still produce valid signatures' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'shares.json')
      sf = described_class.from_keygen('CMP20-ECDSA-P256', kg)
      sf.save(path)

      loaded = described_class.load(path)
      sig = Confium::TC::Cmp20.sign(loaded.shares.first(2), 2, 'round-trip')

      # Verify under the loaded public key.
      require 'openssl'
      asn1 = OpenSSL::ASN1::Sequence([
                                       OpenSSL::ASN1::Sequence([
                                                                 OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                                 OpenSSL::ASN1::ObjectId('prime256v1')
                                                               ]),
                                       OpenSSL::ASN1::BitString(loaded.public_key)
                                     ])
      pkey = OpenSSL::PKey::EC.new(asn1.to_der)
      r = OpenSSL::BN.new(sig[0, 32], 2)
      s = OpenSSL::BN.new(sig[32, 32], 2)
      der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
      digest = OpenSSL::Digest.digest('SHA256', 'round-trip')
      expect(pkey.dsa_verify_asn1(digest, der)).to be(true)
    end
  end

  it 'to_json produces the documented envelope shape' do
    sf = described_class.from_keygen('GG18-ECDSA-P256', kg)
    parsed = JSON.parse(sf.to_json)
    expect(parsed['scheme']).to eq('GG18-ECDSA-P256')
    expect(parsed['party_count']).to eq(3)
    expect(parsed['public_key']).to match(/\A[0-9a-f]{66}\z/)
    expect(parsed['shares'].length).to eq(3)
    expect(parsed['shares'].first).to match(/\A[0-9a-f]{142}\z/)
  end

  it 'is interoperable with the Python binding envelope (shape check)' do
    # The Python confium.tc.ShareFile produces the same JSON shape —
    # see crates/confium-python/python/confium/tc_share_file.py.
    # This spec verifies the Ruby side produces that shape so a file
    # saved in Ruby can be loaded in Python and vice versa.
    sf = described_class.from_keygen('CMP20-ECDSA-P256', kg)
    json = sf.to_json
    parsed = JSON.parse(json)
    expect(parsed.keys.sort).to eq(%w[party_count public_key scheme shares threshold])
  end
end
