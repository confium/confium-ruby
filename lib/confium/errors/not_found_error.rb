# frozen_string_literal: true

# Raised when a referenced slot/cert/share is not present.
class Confium::NotFoundError < Confium::Error
  attr_reader :kind, :identifier

  def initialize(message = nil, kind:, identifier:, **rest)
    @kind = kind
    @identifier = identifier
    super(message, details: { kind: kind, identifier: identifier, **rest })
  end
end
