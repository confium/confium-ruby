# frozen_string_literal: true

# Raised when a Shamir/threshold operation fails (insufficient shares,
# duplicate coordinates, etc.).
class Confium::ThresholdError < Confium::Error
  attr_reader :have_count, :need_count

  def initialize(message = nil, have_count:, need_count:, **rest)
    @have_count = have_count
    @need_count = need_count
    super(message, details: { have_count: have_count, need_count: need_count, **rest })
  end
end
