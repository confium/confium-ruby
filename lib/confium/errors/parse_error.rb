# frozen_string_literal: true

# Raised when input cannot be parsed (bad JSON, malformed PEM, etc.).
class Confium::ParseError < Confium::Error
  attr_reader :format, :offset

  def initialize(message = nil, format: nil, offset: nil, **rest)
    @format = format
    @offset = offset
    super(message, details: { format: format, offset: offset, **rest })
  end
end
