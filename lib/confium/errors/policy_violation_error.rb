# frozen_string_literal: true

# Raised when a FIPS / jurisdictional policy is violated.
class Confium::PolicyViolationError < Confium::Error
  attr_reader :policy, :violation

  def initialize(message = nil, policy:, violation:, **rest)
    @policy = policy
    @violation = violation
    super(message, details: { policy: policy, violation: violation, **rest })
  end
end
