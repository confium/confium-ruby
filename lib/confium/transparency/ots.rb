# frozen_string_literal: true

# Confium::Transparency::OTS — OpenTimestamps client interface.
#
# Wraps confium-transparency::ots::Client for anchoring Merkle tree
# roots in the Bitcoin blockchain via OTS calendar servers.
#
# This is a pure-Ruby stub that defines the interface. The actual
# OTS stamping requires network access to calendar servers and
# will be wired through the Rust extension in a future PR
# (TODO.completion/011-ots-ers-exposure.md).

module Confium
  module Transparency
    module OTS
      # Default OTS calendar servers (from opentimestamps.org).
      DEFAULT_CALENDARS = %w[
        https://a.pool.opentimestamps.org
        https://b.pool.opentimestamps.org
        https://a.pool.eternitywall.com
      ].freeze

      # An OTS receipt proving that a hash was anchored in Bitcoin
      # at a specific block height.
      class Receipt
        attr_reader :bytes, :block_height

        def initialize(bytes:, block_height: nil)
          @bytes = bytes
          @block_height = block_height
        end

        def to_bytes
          @bytes
        end
      end

      # Stamp a 32-byte hash via OTS calendar servers.
      # Returns a Receipt (stub: returns nil — requires network).
      #
      # @param hash [String] 32-byte SHA-256 hash to anchor
      # @return [Receipt, nil]
      def self.stamp(_hash)
        # Real implementation: calls the Rust OTS client which
        # submits the hash to calendar servers and returns a
        # merged proof. Requires network access.
        nil
      end

      # Verify an OTS receipt against a hash.
      # Returns true if the receipt proves the hash was anchored.
      #
      # @param receipt [Receipt, String] the OTS proof
      # @param hash [String] the 32-byte hash
      # @return [Boolean]
      def self.verify(_receipt, _hash)
        # Real implementation: calls the Rust OTS verifier which
        # walks the Bitcoin blockchain proof.
        false
      end
    end
  end
end
