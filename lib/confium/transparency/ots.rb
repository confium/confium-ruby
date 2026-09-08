# frozen_string_literal: true

# Confium::Transparency::OTS — OpenTimestamps calendar client.
#
# Real wire-protocol implementation over the native extension
# (confium-transparency 0.8.5+): stamps POST the 32-byte digest to a
# calendar server and parse the returned partial proof; verification
# replays the op tree from the digest and classifies attestations.
# Network failures raise (Confium::Transparency::OTS is backed by a
# real HTTP client) — there is no silent nil.

module Confium
  module Transparency
    module OTS
      # Default OTS calendar servers (from opentimestamps.org).
      DEFAULT_CALENDARS = %w[
        https://a.pool.opentimestamps.org
        https://b.pool.opentimestamps.org
        https://a.pool.eternitywall.com
      ].freeze

      class << self
        # Stamp a 32-byte digest via the default calendar pool.
        # Returns a Proof (pending attestation — Bitcoin confirmation
        # arrives later; poll with #upgrade).
        #
        # @param hash [String] 32-byte SHA-256 digest to anchor
        # @return [Confium::Transparency::OTS::Proof]
        # @raise [IOError, ArgumentError]
        def stamp(hash)
          default_client.stamp(hash)
        end

        # Verify a proof: replay its op tree from the digest and
        # classify the attestations.
        #
        # @param proof [Proof, String] the proof (or raw .ots bytes —
        #   pass the digest alongside for the String form)
        # @param digest [String, nil] required when proof is bytes
        # @return [Hash] { pending: [uri], bitcoin: [height],
        #   litecoin: [height], anchored: bool }
        def verify(proof, digest = nil)
          proof = Proof.new(digest, proof) if digest && proof.is_a?(String)
          proof.verify
        end

        # Upgrade a pending proof (fetch a more complete one).
        #
        # @return [Proof]
        def upgrade(proof)
          default_client.upgrade(proof)
        end

        private

        def default_client
          @default_client ||= Client.new(DEFAULT_CALENDARS)
        end
      end

      # The native Client is defined by the extension
      # (Confium::Transparency::OTS::Client) with #stamp / #upgrade;
      # the Proof class carries #digest / #to_bytes / #verify.
    end
  end
end
