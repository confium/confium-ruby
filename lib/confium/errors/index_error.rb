# frozen_string_literal: true

# Raised when an out-of-range index is supplied.
class Confium::IndexError < Confium::Error
  attr_reader :index, :valid_range

  def initialize(message = nil, details_hash = nil, **kwargs)
    message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
    @index = kwargs.delete(:index)
    @valid_range = kwargs.delete(:valid_range)
    super(message, details: { index: @index, valid_range: @valid_range, **kwargs })
  end
end
