# frozen_string_literal: true

module Confium
  module TC
    # One threshold-signing session: the state machine and the combine
    # behind every coordinator surface. Coordinator (in-process) and
    # NetworkCoordinator (TCP/NDJSON) are adapters over this class —
    # they own registries and framing; the session owns the semantics:
    #
    #   pending → commitments_collected (T distinct commitments)
    #          → completed (aggregate runs the scheme combine)
    #
    # Aggregate may be called again after completion — the combine
    # randomizes its nonce, so each call yields a fresh (verifiable)
    # signature over the same shares, which is what a network client
    # retrying after a dropped response needs.
    #
    # Signer identity is load-bearing: one signer submitting two
    # shares must never count twice toward the threshold, so
    # commitments and shares are keyed by signer_id and duplicates
    # raise.
    class SigningSession
      DEFAULT_UNLOCK_WINDOW = 14_400

      SCHEMES = {
        'CMP20-ECDSA-P256' => ->(shares, threshold, message) { Cmp20.sign(shares, threshold, message) },
        'GG18-ECDSA-P256' => ->(shares, threshold, message) { Gg18.sign(shares, threshold, message) }
      }.freeze

      attr_reader :message, :threshold, :unlock_window, :scheme, :state

      def initialize(message:, threshold:, unlock_window: DEFAULT_UNLOCK_WINDOW, scheme: 'CMP20-ECDSA-P256')
        raise ArgumentError, "unknown scheme: #{scheme} (known: #{SCHEMES.keys.join(', ')})" unless SCHEMES.key?(scheme)

        @message = message
        @threshold = threshold
        @unlock_window = unlock_window
        @scheme = scheme
        @state = :pending
        # @type ivar @commitments: Hash[String, String]
        @commitments = {}
        # @type ivar @shares: Hash[String, String]
        @shares = {}
      end

      def add_commitment(signer_id, commitment_bytes)
        record(@commitments, signer_id, commitment_bytes)
        @state = :commitments_collected if @commitments.length >= @threshold
        self
      end

      def add_share(signer_id, share_bytes)
        record(@shares, signer_id, share_bytes)
        self
      end

      def commitment_count
        @commitments.length
      end

      def share_count
        @shares.length
      end

      def threshold_met?
        @shares.length >= @threshold
      end

      def aggregate
        unless threshold_met?
          raise ThresholdError.new('Threshold not met', have_count: @shares.length, need_count: @threshold)
        end

        signature = SCHEMES.fetch(@scheme).call(@shares.values, @threshold, @message)
        @state = :completed
        signature
      end

      private

      def record(store, signer_id, bytes)
        if store.key?(signer_id)
          raise ValidationError.new(
            "duplicate submission from signer #{signer_id}",
            param: :signer_id, expected: 'one submission per signer', actual: signer_id
          )
        end

        store[signer_id] = bytes
      end
    end
  end
end
