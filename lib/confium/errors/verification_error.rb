# frozen_string_literal: true

# Raised when a signature / hash / proof fails to verify.
class Confium::VerificationError < Confium::Error
  attr_reader :signer_index, :algorithm

  def initialize(message = nil, signer_index: nil, algorithm: nil, **rest)
    @signer_index = signer_index
    @algorithm = algorithm
    super(message, details: { signer_index: signer_index, algorithm: algorithm, **rest })
  end
end
