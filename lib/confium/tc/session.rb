# frozen_string_literal: true

require "confium/lib"

# Confium::TC::Session wraps a threshold cryptography session.
#
# A session represents one signing or decryption operation involving
# T-of-N parties. The session goes through states: pending →
# commitments_collected → shares_collected → completed.
#
# Usage:
#   session = Confium::TC::Session.new(scheme: "FROST-ed25519",
#                                      threshold: 3,
#                                      num_parties: 5,
#                                      party_index: 0)
#   session.set_local_share(share_bytes)
#   session.round(incoming_messages) # returns outgoing messages
#   result = session.result if session.complete?
module Confium
  module TC
    class Session
      attr_reader :scheme, :threshold, :num_parties, :party_index, :state

      def initialize(scheme:, threshold:, num_parties:, party_index:)
        @scheme = scheme
        @threshold = threshold
        @num_parties = num_parties
        @party_index = party_index
        @state = :pending
        @local_share = nil
        @result = nil
      end

      def set_local_share(share_bytes)
        raise ArgumentError, "share must be a String" unless share_bytes.is_a?(String)
        @local_share = share_bytes
      end

      def complete?
        @state == :completed
      end

      def result
        raise "Session not complete" unless complete?
        @result
      end
    end
  end
end
