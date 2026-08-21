# frozen_string_literal: true

# Raised when a Shamir/threshold operation fails (insufficient shares,
# duplicate coordinates, etc.).
module Confium
  class ThresholdError < Confium::Error
    attr_reader :have_count, :need_count

    def initialize(message = nil, details_hash = nil, **kwargs)
      message, kwargs = Confium::Errors::Coerce.args(message, details_hash, kwargs)
      @have_count = kwargs.delete(:have_count)
      @need_count = kwargs.delete(:need_count)
      super(message, details: { have_count: @have_count, need_count: @need_count, **kwargs })
    end
  end
end
