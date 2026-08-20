# frozen_string_literal: true

# Raised when a referenced slot/cert/share is not present.
class Confium::NotFoundError < Confium::Error
  attr_reader :kind, :identifier

  def initialize(message = nil, details_hash = nil, **kwargs)
    message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
    @kind = kwargs.delete(:kind)
    @identifier = kwargs.delete(:identifier)
    super(message, details: { kind: @kind, identifier: @identifier, **kwargs })
  end
end
