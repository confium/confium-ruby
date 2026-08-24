# frozen_string_literal: true

# Confium::TC::Coordinator coordinates an in-process threshold
# signing session: signers submit commitments and shares at their own
# pace; once the threshold is met, aggregation runs the real
# threshold-ECDSA combine (CMP20 or GG18) and returns a 64-byte
# (r, s) signature verifiable under the quorum public key.
#
# The session semantics (state machine, duplicate-signer rejection,
# the combine) live in SigningSession; this class is the session
# registry and quorum-scoped entry point. NetworkCoordinator is the
# TCP/NDJSON adapter over the same sessions.
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

      def create_session(message:, threshold:, unlock_window: SigningSession::DEFAULT_UNLOCK_WINDOW,
                         scheme: 'CMP20-ECDSA-P256')
        session_id = "session-#{@sessions.length + 1}"
        @sessions[session_id] = SigningSession.new(
          message: message, threshold: threshold,
          unlock_window: unlock_window, scheme: scheme
        )
        session_id
      end

      def session_state(session_id)
        fetch(session_id).state
      end

      def submit_commitment(session_id, signer_id, commitment_bytes)
        fetch(session_id).add_commitment(signer_id, commitment_bytes)
      end

      def submit_share(session_id, signer_id, share_bytes)
        fetch(session_id).add_share(signer_id, share_bytes)
      end

      def aggregate(session_id)
        fetch(session_id).aggregate
      end

      private

      def fetch(session_id)
        @sessions.fetch(session_id) do
          raise NotFoundError.new("Unknown session: #{session_id}", kind: :session, identifier: session_id)
        end
      end
    end
  end
end
