# frozen_string_literal: true

# Raised when a signature / hash / proof fails to verify.
module Confium
  class VerificationError < Confium::Error
    attr_reader :signer_index, :algorithm

    def initialize(message = nil, details_hash = nil, **kwargs)
      message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
      @signer_index = kwargs.delete(:signer_index)
      @algorithm = kwargs.delete(:algorithm)
      super(message, details: { signer_index: @signer_index, algorithm: @algorithm, **kwargs })
    end
  end
end
