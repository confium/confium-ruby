# frozen_string_literal: true

# Root of all Confium errors. Loaded by every subclass file.
module Confium
  module Errors
    # Marker namespace for error-hierarchy internals. `Coerce` lives
    # under here so subclasses can reference it as
    # `Confium::Errors::Coerce.args(...)` without polluting the
    # top-level `Confium` namespace.
  end

  class Error < StandardError
    attr_reader :details

    # The native extension constructs errors positionally
    # (message, details_hash) — the same shape every typed subclass
    # accepts via Errors::Coerce. Accepting it here keeps the whole
    # family uniform; the keyword form still works.
    def initialize(message = nil, details_hash = nil, details: {})
      base = if details_hash.is_a?(Hash) && !details_hash.empty?
               details_hash
             else
               details
             end
      @details = base.transform_keys(&:to_sym)
      super(message)
    end

    def to_h
      { class: self.class.name, message: message, details: details }
    end
  end
end

require_relative 'errors/coerce'
