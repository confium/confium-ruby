# frozen_string_literal: true

# Raised when a FIPS / jurisdictional policy is violated.
module Confium
  class PolicyViolationError < Confium::Error
    attr_reader :policy, :violation

    def initialize(message = nil, details_hash = nil, **kwargs)
      message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
      @policy = kwargs.delete(:policy)
      @violation = kwargs.delete(:violation)
      super(message, details: { policy: @policy, violation: @violation, **kwargs })
    end
  end
end
