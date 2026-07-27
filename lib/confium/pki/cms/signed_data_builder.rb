# frozen_string_literal: true

require "json"

# Confium::PKI::CMS::SignedDataBuilder — construct CMS SignedData
# envelopes with one or more signers.
#
# Usage:
#   builder = Confium::PKI::CMS::SignedDataBuilder.new
#   builder.content_type = "1.2.840.113549.1.7.1"
#   builder.content = "hello world".b
#   builder.add_signer(cert_der: der_bytes, private_key: key_bytes, algorithm: :ed25519)
#   sd = builder.build
#   sd.to_json  # => JSON wire format

module Confium
  module PKI
    module CMS
      class SignedDataBuilder
        attr_accessor :content_type, :content

        def initialize
          @content_type = "1.2.840.113549.1.7.1"
          @content = nil
          @signers = []
          @certificates = []
        end

        def add_signer(cert_der:, private_key:, algorithm:)
          @certificates << cert_der
          @signers << {
            cert_der: cert_der,
            private_key: private_key,
            algorithm: algorithm,
          }
        end

        def add_certificate(cert_der)
          @certificates << cert_der
        end

        # Build a SignedData JSON model. The signer_infos contain
        # pre-computed signatures for each signer.
        #
        # @return [Confium::PKI::CMS::SignedData]
        def build
          content_bytes = @content ? @content.bytes : nil

          signer_infos = @signers.map do |s|
            sig = case s[:algorithm]
                  when :ed25519
                    Confium::Composite.sign_ed25519(s[:private_key], @content || "")
                  when :ecdsa_p256
                    Confium::TC::FrostP256.sign(s[:private_key], @content || "")
                  else
                    raise ArgumentError, "unsupported algorithm: #{s[:algorithm]}"
                  end

            {
              "version" => 1,
              "sid" => { "kind" => "subject_key_identifier", "key_identifier" => s[:cert_der].bytes.first(20) },
              "digest_algorithm" => { "oid" => "2.16.840.1.101.3.4.2.1" },
              "signed_attrs" => [],
              "signature_algorithm" => {
                "oid" => case s[:algorithm]
                         when :ed25519 then "1.3.101.112"
                         when :ecdsa_p256 then "1.2.840.10045.4.3.2"
                         end,
              },
              "signature" => sig["signature"]&.bytes || sig["signature"]&.bytes || [],
            }
          end

          json = {
            "version" => 1,
            "digest_algorithms" => [{ "oid" => "2.16.840.1.101.3.4.2.1" }],
            "encap_content_info" => {
              "content_type" => @content_type,
              "content" => content_bytes,
            }.compact,
            "certificates" => @certificates.map(&:bytes),
            "signer_infos" => signer_infos,
          }.to_json

          Confium::PKI::CMS::SignedData.from_json(json)
        end
      end
    end
  end
end
