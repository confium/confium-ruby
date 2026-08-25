# frozen_string_literal: true

require 'confium'
require 'fileutils'
require 'time'
require_relative '../cert_fixture'

RSpec.describe Confium::PKI::Certificate do
  let(:pem) { File.read(File.expand_path('support/test.pem', __dir__)) }
  let(:cert) { described_class.from_pem(pem) }

  before(:all) do
    support_dir = File.expand_path('support', __dir__)
    FileUtils.mkdir_p(support_dir)
    pem_path = File.join(support_dir, 'test.pem')
    CertFixture.write_pem(pem_path) unless File.exist?(pem_path)
  end

  describe '.from_pem' do
    it 'parses a PEM-encoded X.509 certificate' do
      expect(cert).to be_a(described_class)
    end

    it 'raises on malformed PEM' do
      expect do
        described_class.from_pem('not a cert')
      end.to raise_error(Confium::ParseError)
    end
  end

  describe '.from_der' do
    it 'round-trips through to_der' do
      der = cert.to_der
      expect(der).to be_a(String)
      expect(der.encoding).to eq(Encoding::ASCII_8BIT)
      round = described_class.from_der(der)
      expect(round.fingerprint_sha256).to eq(cert.fingerprint_sha256)
    end

    it 'reports the exact truncation offset for incomplete DER' do
      der = cert.to_der
      expect(der.bytesize).to be > 40

      error = nil
      begin
        described_class.from_der(der.byteslice(0, 20))
      rescue Confium::ParseError => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.offset).to eq(20)
    end
  end

  describe '#fingerprint_sha256' do
    it 'returns a 64-char hex string' do
      fp = cert.fingerprint_sha256
      expect(fp).to match(/\A[0-9a-f]{64}\z/)
    end
  end

  describe '#serial_hex' do
    it 'returns the serial number as hex' do
      expect(cert.serial_hex).to match(/\A[0-9a-f]+\z/)
    end
  end

  describe '#not_before / #not_after' do
    it 'returns ISO8601 timestamps' do
      expect(cert.not_before).to match(/\A\d{4}-\d{2}-\d{2}T/)
      expect(cert.not_after).to match(/\A\d{4}-\d{2}-\d{2}T/)
    end
  end

  describe '#valid_at?' do
    it 'returns true for a time inside the validity window' do
      expect(cert.valid_at?(Time.now.utc.iso8601)).to be(true)
    end

    it 'returns false for a time after expiry' do
      expect(cert.valid_at?('3030-01-01T00:00:00Z')).to be(false)
    end

    it 'raises ArgumentError for a malformed timestamp' do
      expect do
        cert.valid_at?('not a time')
      end.to raise_error(ArgumentError, /invalid ISO8601 time/)
    end
  end

  describe '#public_key_bytes' do
    it 'returns a non-empty binary string' do
      pk = cert.public_key_bytes
      expect(pk).to be_a(String)
      expect(pk.encoding).to eq(Encoding::ASCII_8BIT)
      expect(pk.bytesize).to be > 0
    end
  end
end

RSpec.describe Confium::PKI::CSR do
  before(:all) do
    support_dir = File.expand_path('support', __dir__)
    FileUtils.mkdir_p(support_dir)
    csr_path = File.join(support_dir, 'test.csr')
    unless File.exist?(csr_path)
      require 'openssl'
      key = OpenSSL::PKey::RSA.new(2048)
      csr = OpenSSL::X509::Request.new
      csr.subject = OpenSSL::X509::Name.parse('/CN=test.example.com/O=Confium Test')
      csr.public_key = key
      csr.sign(key, OpenSSL::Digest.new('SHA256'))
      File.write(csr_path, csr.to_pem)
    end
  end

  let(:pem) { File.read(File.expand_path('support/test.csr', __dir__)) }

  it 'round-trips PEM → DER → PEM' do
    csr = described_class.from_pem(pem)
    der = csr.to_der
    expect(der.encoding).to eq(Encoding::ASCII_8BIT)
    csr2 = described_class.from_der(der)
    expect(csr2.to_pem).to eq(csr.to_pem)
  end

  it 'raises on a malformed DER byte sequence' do
    bad = String.new("\x00\x00\x00", encoding: Encoding::ASCII_8BIT)
    expect do
      described_class.from_der(bad)
    end.to raise_error(Confium::ParseError, /SEQUENCE/)
  end
end

RSpec.describe Confium::PKI::CMS::SignedData do
  let(:cms_json) do
    '{
      "version": 1,
      "digest_algorithms": [{"oid":"2.16.840.1.101.3.4.2.1"}],
      "encap_content_info": {
        "content_type":"1.2.840.113549.1.7.1",
        "content":[72,101,108,108,111]
      },
      "certificates":[],
      "signer_infos":[]
    }'
  end

  describe '.from_json' do
    it 'parses a CMS SignedData JSON model' do
      sd = described_class.from_json(cms_json)
      expect(sd).to be_a(described_class)
    end

    it 'raises on invalid JSON' do
      expect { described_class.from_json('{not json') }.to raise_error(Confium::ParseError)
    end
  end

  describe '#to_json' do
    it 'round-trips through from_json' do
      sd = described_class.from_json(cms_json)
      round = described_class.from_json(sd.to_json)
      expect(round.content_type).to eq(sd.content_type)
      expect(round.signer_count).to eq(sd.signer_count)
    end
  end

  describe '#content_type' do
    it 'returns the OID string' do
      sd = described_class.from_json(cms_json)
      expect(sd.content_type).to eq('1.2.840.113549.1.7.1')
    end
  end

  describe '#content' do
    it 'returns a Content object when content is present' do
      sd = described_class.from_json(cms_json)
      content = sd.content
      expect(content).to be_a(Confium::PKI::CMS::Content)
      expect(content.bytes.bytesize).to eq(5)
      expect(content.bytes.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'returns nil for a detached signature (no content)' do
      detached = described_class.from_json('{
        "version": 1,
        "digest_algorithms": [],
        "encap_content_info": {"content_type":"1.2.840.113549.1.7.1"},
        "certificates":[],
        "signer_infos":[]
      }')
      expect(detached.content).to be_nil
    end
  end

  describe '#signer_count' do
    it 'returns the number of signer infos' do
      sd = described_class.from_json(cms_json)
      expect(sd.signer_count).to eq(0)
    end
  end
end

RSpec.describe Confium::PKI::XMLDSig do
  describe '.canonicalize' do
    it 'strips the XML declaration' do
      xml = %(<?xml version="1.0"?>\n<root>\n  <child>text</child>\n</root>)
      result = described_class.canonicalize(xml)
      expect(result).to include('<root>')
      expect(result).not_to include('<?xml')
    end

    it 'preserves element content' do
      xml = %(<root><child attr="val">hello</child></root>)
      result = described_class.canonicalize(xml)
      expect(result).to include('hello')
      expect(result).to include(%(attr="val"))
    end

    it 'raises on malformed XML' do
      expect do
        described_class.canonicalize('&&&unterminated entity')
      end.to raise_error(Confium::ParseError, /malformed XML/)
    end
  end

  describe '.canonicalize_exclusive' do
    it 'round-trips the same as canonicalize for simple inputs' do
      xml = '<root><child>x</child></root>'
      expect(described_class.canonicalize_exclusive(xml)).to eq(described_class.canonicalize(xml))
    end
  end
end

RSpec.describe Confium::PKI::CMS::SignedData do
  describe '#verify_signatures' do
    it 'returns a result object even with no signers' do
      sd = described_class.from_json('{
        "version": 1,
        "digest_algorithms": [],
        "encap_content_info": {"content_type":"1.2.840.113549.1.7.1"},
        "certificates":[],
        "signer_infos":[]
      }')
      result = sd.verify_signatures('payload')
      expect(result).to be_a(Confium::PKI::CMS::VerificationResult)
      expect(result.all_verified?).to be(true)
      expect(result.signer_count).to eq(0)
      expect(result.per_signer_json).to eq('[]')
    end
  end
end

RSpec.describe Confium::PKI::CMS::SignedData, '#to_der' do
  it 'encodes a SignedData as RFC 5652 ContentInfo DER' do
    sd_json = '{
      "version": 1,
      "digest_algorithms": [{"oid":"2.16.840.1.101.3.4.2.1"}],
      "encap_content_info": {
        "content_type":"1.2.840.113549.1.7.1",
        "content":[72,101,108,108,111]
      },
      "certificates":[],
      "signer_infos":[]
    }'
    sd = described_class.from_json(sd_json)
    der = sd.to_der
    expect(der).to be_a(String)
    expect(der.encoding).to eq(Encoding::ASCII_8BIT)
    # Outer SEQUENCE tag = 0x30 per RFC 5652 §3.
    expect(der.bytes.first).to eq(0x30)
  end
end

RSpec.describe Confium::PKI::CMS::SignedData, '.build_detached' do
  let(:ed25519_keypair) { Confium::Composite.generate_ed25519_keypair }
  let(:private_key) { ed25519_keypair['private_key'] }
  let(:fake_cert_der) { "0\x82\u0001\u0000#{'X' * 256}".b }

  it 'builds a detached SignedData from a pre-computed signature' do
    message = 'hello cms sign path'
    signature = Confium::Composite.sign_ed25519(private_key, message).fetch('signature')

    sd = described_class.build_detached(
      signature,
      '1.3.101.112', # Ed25519 OID
      [fake_cert_der]
    )

    expect(sd).to be_a(described_class)
    expect(sd.signer_count).to eq(1)
    expect(sd.content).to be_nil # detached
  end

  it 'encodes to DER' do
    signature = Confium::Composite.sign_ed25519(private_key, 'payload').fetch('signature')
    sd = described_class.build_detached(
      signature,
      '1.3.101.112',
      [fake_cert_der]
    )
    der = sd.to_der
    expect(der.bytes.first).to eq(0x30)
    expect(der.bytesize).to be > 300
  end

  it 'round-trips through JSON' do
    signature = Confium::Composite.sign_ed25519(private_key, 'round-trip').fetch('signature')
    sd = described_class.build_detached(
      signature,
      '1.3.101.112',
      [fake_cert_der]
    )
    parsed = described_class.from_json(sd.to_json)
    expect(parsed.signer_count).to eq(1)
  end

  it 'accepts a payload_hash via the Ruby builder' do
    signature = Confium::Composite.sign_ed25519(private_key, 'payload').fetch('signature')
    sd = described_class.build_detached(
      signature,
      '1.3.101.112',
      [fake_cert_der]
    )
    expect(sd.signer_count).to eq(1)
  end

  it 'raises when signature is nil' do
    expect do
      described_class.build_detached(
        nil,
        '1.3.101.112',
        [fake_cert_der]
      )
    end.to raise_error(ArgumentError, /signature/)
  end

  it 'raises when certificates is nil' do
    signature = Confium::Composite.sign_ed25519(private_key, 'x').fetch('signature')
    expect do
      described_class.build_detached(
        signature,
        '1.3.101.112',
        nil
      )
    end.to raise_error(ArgumentError, /certificates/)
  end
end

RSpec.describe Confium::PKI::CMS::SignedDataBuilder do
  let(:ed25519_keypair) { Confium::Composite.generate_ed25519_keypair }
  let(:private_key) { ed25519_keypair['private_key'] }
  let(:fake_cert_der) { "0\x82\u0001\u0000#{'C' * 256}".b }

  it 'builds a detached SignedData end-to-end via the builder' do
    builder = described_class.new
    builder.content = 'builder integration test'.b
    builder.add_signer(cert_der: fake_cert_der, private_key: private_key, algorithm: :ed25519)

    sd = builder.build
    expect(sd).to be_a(Confium::PKI::CMS::SignedData)
    expect(sd.signer_count).to eq(1)
    expect(sd.to_der.bytes.first).to eq(0x30)
  end

  it 'rejects unsupported algorithm' do
    builder = described_class.new
    builder.content = 'x'
    expect do
      builder.add_signer(cert_der: fake_cert_der, private_key: private_key, algorithm: :bogus)
    end.to raise_error(ArgumentError, /unsupported algorithm/)
  end

  it 'requires at least one signer' do
    builder = described_class.new
    builder.content = 'x'
    expect { builder.build }.to raise_error(ArgumentError, /at least one signer/)
  end

  it 'requires content' do
    builder = described_class.new
    builder.add_signer(cert_der: fake_cert_der, private_key: private_key, algorithm: :ed25519)
    expect { builder.build }.to raise_error(ArgumentError, /#content is required/)
  end
end
