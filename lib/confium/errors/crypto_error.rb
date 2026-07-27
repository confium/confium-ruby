# frozen_string_literal: true

# Raised when a primitive-level crypto operation fails (invalid scalar,
# bad key derivation).
class Confium::CryptoError < Confium::Error
  attr_reader :primitive

  def initialize(message = nil, primitive:, **rest)
    @primitive = primitive
    super(message, details: { primitive: primitive, **rest })
  end
end
