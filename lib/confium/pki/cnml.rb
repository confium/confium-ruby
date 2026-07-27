# frozen_string_literal: true

# OIML CNML certificate profile definition.
#
# Defines the required X.509 extensions for measuring instrument
# certificates per OIML R 76 (non-automatic weighing instruments)
# and the broader CNML framework.
#
# This is an interface definition — the actual OIML R 76 PDF is a
# paid publication. The extension OIDs listed here are from public
# OIML documentation and the BIPM/CIPM MRA framework.

module Confium
  module PKI
    module CNML
      # Required X.509 v3 extensions for a CNML certificate.
      REQUIRED_EXTENSIONS = {
        # Standard X.509 extensions required by CNML:
        "2.5.29.19" => "basicConstraints (CA=true for IA certs, CA=false for leaf)",
        "2.5.29.15" => "keyUsage (digitalSignature for signing certs)",
        "2.5.29.37" => "extKeyUsage (id-kp-OCSPSigning or custom CNML OIDs)",
        "2.5.29.14" => "subjectKeyIdentifier (required for CMS signer resolution)",
        "2.5.29.35" => "authorityKeyIdentifier (required for chain building)",
      }.freeze

      # Optional but recommended extensions.
      OPTIONAL_EXTENSIONS = {
        "2.5.29.31" => "cRLDistributionPoints (for revocation checking)",
        "2.5.29.32" => "certificatePolicies (CNML policy OID)",
        "1.3.6.1.5.5.7.1.1" => "authorityInfoAccess (OCSP responder URL)",
      }.freeze

      # CNML certificate roles (maps to ActorType in Confium::Identity).
      CERT_ROLES = %i[
        manufacturer
        testing_lab
        issuing_authority_officer
        biml_director
        quorum_coordinator
        verifier
      ].freeze

      # Validate that a certificate has the required CNML extensions.
      # This is a structural check (extension OID presence), not a
      # semantic check (extension value correctness). Full validation
      # requires the OIML R 76 specification.
      #
      # @param cert [Confium::PKI::Certificate] the cert to check
      # @return [Array<String>] list of missing required extension OIDs
      def self.missing_extensions(_cert)
        # Full implementation requires parsing the cert's extensions,
        # which needs the x509-cert crate exposed through the Ruby
        # extension. For now, returns an empty array (no validation).
        #
        # TODO: when confium-pki exposes Certificate#extensions, walk
        # the extension list and cross-reference against
        # REQUIRED_EXTENSIONS.
        []
      end

      # The list of required extension OIDs.
      # @return [Array<String>]
      def self.required_extension_oids
        REQUIRED_EXTENSIONS.keys
      end

      # The list of optional extension OIDs.
      # @return [Array<String>]
      def self.optional_extension_oids
        OPTIONAL_EXTENSIONS.keys
      end

      # All known CNML certificate roles.
      # @return [Array<Symbol>]
      def self.cert_roles
        CERT_ROLES
      end
    end
  end
end
