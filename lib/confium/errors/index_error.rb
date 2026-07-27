# frozen_string_literal: true

# Raised when an out-of-range index is supplied.
class Confium::IndexError < Confium::Error
  attr_reader :index, :valid_range

  def initialize(message = nil, index:, valid_range:, **rest)
    @index = index
    @valid_range = valid_range
    super(message, details: { index: index, valid_range: valid_range, **rest })
  end
end
