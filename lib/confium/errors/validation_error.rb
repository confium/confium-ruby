# frozen_string_literal: true

# Raised when input is well-formed but semantically invalid (wrong size,
# out-of-range value, etc.).
class Confium::ValidationError < Confium::Error
  attr_reader :param, :expected, :actual

  def initialize(message = nil, details_hash = nil, **kwargs)
    message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
    @param = kwargs.delete(:param)
    @expected = kwargs.delete(:expected)
    @actual = kwargs.delete(:actual)
    super(message, details: { param: @param, expected: @expected, actual: @actual, **kwargs })
  end
end
