# frozen_string_literal: true

# Confium::TC::Coordinator coordinates an in-process threshold
# signing session: signers submit commitments and shares at their own
# pace; once the threshold is met, aggregation runs the real
# threshold-ECDSA combine (CMP20 or GG18 — the same in-process
# drivers behind Confium::TC::Cmp20 / Confium::TC::Gg18) and returns
# a 64-byte (r, s) signature verifiable under the quorum public key.
#
# Usage:
#   coordinator = Confium::TC::Coordinator.new(quorum_id: "biml-root")
#   session_id = coordinator.create_session(message: data,
#                                           threshold: 3,
#                                           scheme: "CMP20-ECDSA-P256")
#   coordinator.submit_commitment(session_id, signer_id, commitment_bytes)
#   # ... wait for T commitments ...
#   coordinator.submit_share(session_id, signer_id, share_bytes)
#   # ... wait for T shares ...
#   signature = coordinator.aggregate(session_id)
module Confium
  module TC
    class Coordinator
      attr_reader :quorum_id, :sessions

      def initialize(quorum_id:)
        @quorum_id = quorum_id
        @sessions = {}
      end

      SCHEMES = {
        'CMP20-ECDSA-P256' => ->(shares, threshold, message) { Cmp20.sign(shares, threshold, message) },
        'GG18-ECDSA-P256' => ->(shares, threshold, message) { Gg18.sign(shares, threshold, message) }
      }.freeze

      def create_session(message:, threshold:, unlock_window: 14_400, scheme: 'CMP20-ECDSA-P256')
        raise ArgumentError, "unknown scheme: #{scheme} (known: #{SCHEMES.keys.join(', ')})" unless SCHEMES.key?(scheme)

        session_id = "session-#{@sessions.length + 1}"
        @sessions[session_id] = {
          message: message,
          threshold: threshold,
          unlock_window: unlock_window,
          scheme: scheme,
          state: :pending,
          commitments: [],
          shares: []
        }
        session_id
      end

      def session_state(session_id)
        @sessions.dig(session_id, :state)
      end

      def submit_commitment(session_id, signer_id, commitment_bytes)
        session = @sessions[session_id] or raise "Unknown session: #{session_id}"
        session[:commitments] << { signer_id: signer_id, bytes: commitment_bytes }
        return unless session[:commitments].length >= session[:threshold]

        session[:state] = :commitments_collected
      end

      def submit_share(session_id, signer_id, share_bytes)
        session = @sessions[session_id] or raise "Unknown session: #{session_id}"
        session[:shares] << { signer_id: signer_id, bytes: share_bytes }
      end

      def aggregate(session_id)
        session = @sessions[session_id] or raise "Unknown session: #{session_id}"
        raise ThresholdError, 'Threshold not met' if session[:shares].length < session[:threshold]

        session[:state] = :completed
        SCHEMES.fetch(session[:scheme]).call(
          session[:shares].map { |s| s[:bytes] },
          session[:threshold],
          session[:message]
        )
      end
    end
  end
end
