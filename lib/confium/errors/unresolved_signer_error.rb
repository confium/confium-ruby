# frozen_string_literal: true

# Raised when a CMS signer_info cannot be resolved to a certificate.
class Confium::UnresolvedSignerError < Confium::Error
  attr_reader :signer_index

  def initialize(message = nil, signer_index:, **rest)
    @signer_index = signer_index
    super(message, details: { signer_index: signer_index, **rest })
  end
end
