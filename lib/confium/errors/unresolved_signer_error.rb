# frozen_string_literal: true

# Raised when a CMS signer_info cannot be resolved to a certificate.
class Confium::UnresolvedSignerError < Confium::Error
  attr_reader :signer_index

  def initialize(message = nil, details_hash = nil, **kwargs)
    message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
    @signer_index = kwargs.delete(:signer_index)
    super(message, details: { signer_index: @signer_index, **kwargs })
  end
end
