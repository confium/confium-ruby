# frozen_string_literal: true

# Shared coercion helper for the typed-error hierarchy.
#
# Every `Confium::*Error` subclass accepts the same three calling
# conventions (keyword form, positional-Hash form from the native
# extension, hash-only form). Before this module existed, each class
# duplicated the same 8-line coercion preamble. Centralizing it here
# keeps the per-class initializer focused on its own field extraction.
#
# Usage in a subclass:
#
#     def initialize(message = nil, details_hash = nil, **kwargs)
#       message, kwargs = Coerce.args(message, details_hash, kwargs)
#       @have_count = kwargs.delete(:have_count)
#       @need_count = kwargs.delete(:need_count)
#       super(message, details: { have_count: @have_count, need_count: @need_count, **kwargs })
#     end
module Confium
  module Errors
    module Coerce
      module_function

      # Normalize the (message, details_hash, kwargs) triple that every
      # typed-error initializer receives. Returns `[message, kwargs]`
      # where:
      #
      # - `message` is `nil` or a String (never a Hash)
      # - `kwargs` is a Hash with symbol keys, containing every key
      #   from the original `details_hash` and `**kwargs`, plus
      #   anything that was tucked inside `message` (when the caller
      #   passed a Hash as the first arg).
      #
      # The subclass initializer then `kwargs.delete(:specific_field)`
      # to pull its own fields out, and the leftover `**kwargs` flows
      # to `super` as `details:`.
      def args(message, details_hash, kwargs)
        if message.is_a?(Hash)
          kwargs = message.transform_keys(&:to_sym).merge(kwargs)
          message = kwargs.delete(:message)
        end
        kwargs = details_hash.transform_keys(&:to_sym).merge(kwargs) if details_hash.is_a?(Hash)
        [message, kwargs]
      end
    end
  end
end
