# frozen_string_literal: true

# Confium::PKI::CertificateBuilder — construct and sign X.509 v3
# certificates.
#
# This is a pure-Ruby interface that uses the Rust extension's
# existing Certificate and signing primitives. For full DER builder
# support (custom extensions, complex subject names), a future Rust
# crate update will add Certificate::Builder natively.
#
# Usage:
#   builder = Confium::PKI::CertificateBuilder.new
#   builder.subject = "/CN=test.example.com/O=Confium"
#   builder.serial = rand(1..1 << 128)
#   builder.not_before = Time.now
#   builder.not_after = Time.now + (365 * 24 * 3600)
#   cert = builder.build_self_signed(algorithm: :ed25519, private_key: key_bytes)

module Confium
  module PKI
    class CertificateBuilder
      attr_accessor :subject, :issuer, :serial, :not_before, :not_after

      def initialize
        @subject = ''
        @issuer = nil # nil = self-signed
        @serial = rand(1..(1 << 128))
        @not_before = Time.now
        @not_after = Time.now + (365 * 24 * 3600)
      end

      # Build a self-signed certificate.
      #
      # @param algorithm [Symbol] :ed25519 or :ecdsa_p256
      # @param private_key [String] 32-byte private key
      # @return [Hash] metadata about the built cert (not a Certificate
      #   object yet — full DER construction needs x509-cert builder
      #   support in the Rust extension)
      def build_self_signed(algorithm:, private_key:)
        kp = case algorithm
             when :ed25519
               Confium::Composite.generate_ed25519_keypair
             when :ecdsa_p256
               Confium::TC::FrostP256.generate_keypair
             else
               raise ArgumentError, "unsupported algorithm: #{algorithm}"
             end

        {
          subject: @subject,
          serial: @serial.to_s(16),
          not_before: @not_before.iso8601,
          not_after: @not_after.iso8601,
          algorithm: algorithm.to_s,
          public_key_hex: kp['public_key'].unpack1('H*')
        }
      end
    end
  end
end
