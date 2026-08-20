# frozen_string_literal: true

# Raised when input cannot be parsed (bad JSON, malformed PEM, etc.).
class Confium::ParseError < Confium::Error
  attr_reader :format, :offset

  def initialize(message = nil, details_hash = nil, **kwargs)
    message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
    @format = kwargs.delete(:format)
    @offset = kwargs.delete(:offset)
    super(message, details: { format: @format, offset: @offset, **kwargs })
  end
end
