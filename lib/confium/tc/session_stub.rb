# frozen_string_literal: true

# Confium::TC::SessionStub — placeholder for the multi-party TC session
# interface. The full Session implementation wraps
# confium_tc::session::Session which drives 3-round FROST/CMP20/GG18
# signing ceremonies.
#
# This stub provides the interface shape so consumers can write code
# against it. The actual session orchestration will be wired through
# magnus in a future PR (TODO.completion/009-multi-party-tc-sessions.md).

module Confium
  module TC
    class SessionStub
      attr_reader :scheme, :threshold, :party_count, :this_party_idx, :round

      def initialize(scheme:, threshold:, party_count:, this_party_idx:)
        @scheme = scheme
        @threshold = threshold
        @party_count = party_count
        @this_party_idx = this_party_idx
        @round = 0
        @complete = false
      end

      def complete?
        @complete
      end

      # Stub: returns an empty RoundResult. Real implementation will
      # call confium_tc::session::Session::round_step.
      def round_step(_incoming_messages)
        @round += 1
        @complete = @round >= 3  # FROST is 3 rounds
        { outgoing: [], complete: @complete }
      end

      def result
        nil  # Real implementation returns the signature/secret bytes.
      end
    end
  end
end
