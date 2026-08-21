# frozen_string_literal: true

require 'json'
require 'digest'

# Confium::PKI::CMS::SignedDataBuilder — construct CMS SignedData
# envelopes with one or more signers.
#
# Delegates to the Rust `confium_pki::cms::build_detached_signature`
# via `Confium::PKI::CMS::SignedData.build_detached`. The Ruby side
# only computes the per-signer signature bytes (via the existing
# Confium::Composite / Confium::TC signers); the envelope assembly
# happens in Rust so the JSON model + DER encoding stay authoritative.
#
# Usage:
#   builder = Confium::PKI::CMS::SignedDataBuilder.new
#   builder.content = "hello world".b
#   builder.add_signer(cert_der: der_bytes, private_key: key_bytes, algorithm: :ed25519)
#   sd = builder.build
#   sd.to_json  # => JSON wire format
#   sd.to_der   # => RFC 5652 ContentInfo DER bytes

module Confium
  module PKI
    module CMS
      class SignedDataBuilder
        attr_accessor :content

        SIGNATURE_ALGORITHM_OID = {
          ed25519: '1.3.101.112',
          ecdsa_p256: '1.2.840.10045.4.3.2'
        }.freeze

        def initialize
          @content = nil
          @signers = []
        end

        def add_signer(cert_der:, private_key:, algorithm:)
          algorithm = algorithm.to_sym unless algorithm.is_a?(Symbol)
          unless SIGNATURE_ALGORITHM_OID.key?(algorithm)
            raise ArgumentError,
                  "unsupported algorithm: #{algorithm.inspect} \
                   (expected one of: #{SIGNATURE_ALGORITHM_OID.keys.join(', ')})"
          end
          @signers << {
            cert_der: cert_der,
            private_key: private_key,
            algorithm: algorithm
          }
        end

        # Build a SignedData with a detached signature over `@content`.
        # For multi-signer composites, the first signer is used as the
        # primary; additional signers are ignored until the upstream
        # Rust `build_detached_signature` supports multi-signer input.
        #
        # @return [Confium::PKI::CMS::SignedData]
        def build
          raise ArgumentError, 'at least one signer is required' if @signers.empty?
          raise ArgumentError, '#content is required (detached builder)' if @content.nil?

          primary = @signers.first
          payload_bytes = @content.respond_to?(:bytes) ? @content.bytes : @content
          signature = sign_payload(primary[:algorithm], primary[:private_key], payload_bytes)
          algorithm_oid = SIGNATURE_ALGORITHM_OID.fetch(primary[:algorithm])

          SignedData.build_detached(
            signature,
            algorithm_oid,
            @signers.map { |s| s[:cert_der] }
          )
        end

        private

        def sign_payload(algorithm, private_key, payload)
          case algorithm
          when :ed25519
            result = Confium::Composite.sign_ed25519(private_key, payload)
            result.fetch('signature')
          when :ecdsa_p256
            result = Confium::TC::FrostP256.sign(private_key, payload)
            result.fetch('signature')
          else
            raise ArgumentError, "unsupported algorithm: #{algorithm.inspect}"
          end
        end
      end
    end
  end
end
