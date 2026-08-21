# frozen_string_literal: true

# Confium::TC::Coordinator wraps the async session coordinator service.
#
# The coordinator enables globally distributed threshold signers to
# participate when convenient — no simultaneity required.
#
# Usage:
#   coordinator = Confium::TC::Coordinator.new(quorum_id: "biml-root")
#   session_id = coordinator.create_session(message: data,
#                                           threshold: 5,
#                                           unlock_window: 14400)
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

      def create_session(message:, threshold:, unlock_window: 14_400)
        session_id = "session-#{@sessions.length + 1}"
        @sessions[session_id] = {
          message: message,
          threshold: threshold,
          unlock_window: unlock_window,
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
        raise 'Threshold not met' if session[:shares].length < session[:threshold]

        session[:state] = :completed
        # In real implementation, calls FFI to aggregate shares
        session[:shares].map { |s| s[:bytes] }.join
      end
    end
  end
end
