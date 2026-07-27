# frozen_string_literal: true

# Root of all Confium errors. Loaded by every subclass file.
module Confium
  class Error < StandardError
    attr_reader :details

    def initialize(message = nil, details: {})
      @details = details.transform_keys(&:to_sym)
      super(message)
    end

    def to_h
      { class: self.class.name, message: message, details: details }
    end
  end
end
