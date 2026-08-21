# frozen_string_literal: true

# Raised when a primitive-level crypto operation fails (invalid scalar,
# bad key derivation).
module Confium
  class CryptoError < Confium::Error
    attr_reader :primitive

    def initialize(message = nil, details_hash = nil, **kwargs)
      message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
      @primitive = kwargs.delete(:primitive)
      super(message, details: { primitive: @primitive, **kwargs })
    end
  end
end
