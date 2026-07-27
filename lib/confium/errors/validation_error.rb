# frozen_string_literal: true

# Raised when input is well-formed but semantically invalid (wrong size,
# out-of-range value, etc.).
class Confium::ValidationError < Confium::Error
  attr_reader :param, :expected, :actual

  def initialize(message = nil, param:, expected:, actual:, **rest)
    @param = param
    @expected = expected
    @actual = actual
    super(message, details: { param: param, expected: expected, actual: actual, **rest })
  end
end
