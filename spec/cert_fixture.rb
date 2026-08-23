# frozen_string_literal: true

# Shared spec fixture: a self-signed certificate PEM generated via
# the openssl stdlib (works on every platform — the openssl CLI and
# /dev/null do not exist on Windows runners).
require 'openssl'

module CertFixture
  module_function

  def write_pem(path, common_name: 'test.example.com')
    key = OpenSSL::PKey::RSA.new(2048)
    cert = build_self_signed(key, common_name)
    File.binwrite(path, cert.to_pem)
    path
  end

  def build_self_signed(key, common_name)
    name = OpenSSL::X509::Name.parse("/CN=#{common_name}/O=Confium Test")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.not_before = Time.now.utc - 3600
    cert.not_after = Time.now.utc + (365 * 24 * 3600)
    cert.public_key = key.public_key
    cert.subject = name
    cert.issuer = name
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end
end
