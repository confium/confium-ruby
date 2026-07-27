# frozen_string_literal: true

# Jurisdictional policy enforcement for Confium.
#
# Different jurisdictions require different algorithms and key sizes:
#   - EU: no RSA < 2048, ECDSA P-256+ accepted, Ed25519 accepted
#   - US: SHA-1 legacy accepted, ECDSA P-256 accepted
#   - China: SM2/SM3/SM4 required (not currently implemented)
#
# Set the active policy via:
#   Confium::Policy.jurisdiction = :eu
#
# When a policy is active, cert verification and signing operations
# check the algorithm/key-size against the policy's allowed list.
# Violations raise Confium::PolicyViolationError.

module Confium
  module Policy
    @jurisdiction = nil
    @fips_mode = false

    # Built-in jurisdictional policies. Each is a Hash mapping
    # algorithm name to minimum key bits.
    JURISDICTIONS = {
      # EU: eIDAS + GDPR alignment. RSA >= 2048, ECDSA P-256+.
      eu: {
        rsa:       2048,
        ecdsa_p256: 256,
        ecdsa_p384: 384,
        ed25519:   256,
        name:      "European Union (eIDAS)",
      },
      # US: NIST SP 800-131A. RSA >= 2048, ECDSA P-256+, SHA-1 legacy.
      us: {
        rsa:       2048,
        ecdsa_p256: 256,
        ecdsa_p384: 384,
        ed25519:   256,
        sha1_legacy: true,
        name:      "United States (NIST SP 800-131A)",
      },
      # OIML CNML: international, follows BIPM recommendations.
      cnml: {
        rsa:       2048,
        ecdsa_p256: 256,
        ecdsa_p384: 384,
        ed25519:   256,
        name:      "OIML CNML (BIPM)",
      },
    }.freeze

    class << self
      # @return [Symbol, nil] the active jurisdiction (:eu, :us, :cnml)
      attr_reader :jurisdiction

      # @return [Boolean] whether FIPS 140 mode is enabled
      attr_reader :fips_mode

      # Set the active jurisdiction. When non-nil, all signing and
      # verification operations check algorithms against the policy.
      # @param value [Symbol, nil] one of JURISDICTIONS.keys or nil
      # @raise [ArgumentError] if value is not a known jurisdiction
      def jurisdiction=(value)
        if value.nil?
          @jurisdiction = nil
          return
        end
        unless JURISDICTIONS.key?(value.to_sym)
          raise ArgumentError,
                "unknown jurisdiction: #{value} (known: #{JURISDICTIONS.keys.join(', ')})"
        end
        @jurisdiction = value.to_sym
      end

      # Enable/disable FIPS 140 mode. When enabled, only FIPS-approved
      # algorithms are accepted. Ed25519 is NOT FIPS-approved (as of
      # FIPS 186-5 draft); ECDSA P-256/P-384 are.
      # @param value [Boolean]
      def fips_mode=(value)
        @fips_mode = !!value
        @jurisdiction = :us if @fips_mode && @jurisdiction.nil?
      end

      # Check whether an algorithm + key size is allowed under the
      # active policy.
      # @param algorithm [String, Symbol] e.g. "rsa", "ecdsa_p256"
      # @param key_bits [Integer] the key size in bits
      # @return [Boolean]
      # @raise [Confium::PolicyViolationError] if the algorithm is
      #   disallowed or the key size is too small
      def check!(algorithm, key_bits:)
        alg = algorithm.to_sym

        if @fips_mode
          # FIPS mode: only FIPS-approved algorithms.
          fips_approved = %i[ecdsa_p256 ecdsa_p384 rsa]
          unless fips_approved.include?(alg)
            raise Confium::PolicyViolationError.new(
              "algorithm #{alg} is not FIPS-approved",
              policy: :fips,
              violation: :unapproved_algorithm,
            )
          end
        end

        return true unless @jurisdiction

        policy = JURISDICTIONS[@jurisdiction]
        return true unless policy

        min_bits = policy[alg]
        return true if min_bits.nil?

        if key_bits < min_bits
          raise Confium::PolicyViolationError.new(
            "#{alg} key size #{key_bits} below #{min_bits} for #{@jurisdiction}",
            policy: @jurisdiction,
            violation: :key_too_small,
          )
        end

        true
      end

      # The list of known jurisdiction identifiers.
      # @return [Array<Symbol>]
      def known_jurisdictions
        JURISDICTIONS.keys
      end

      # Reset all policies to defaults (no jurisdiction, no FIPS).
      def reset!
        @jurisdiction = nil
        @fips_mode = false
      end
    end
  end
end
