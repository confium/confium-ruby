# frozen_string_literal: true

require 'json'

module Confium
  module Composite
    # JSON transport for composite signatures. The native extension
    # defines Signature with algorithms/component_count/verify over
    # component Hashes (algorithm, public_key, signature) whose
    # binary fields cannot ride JSON directly, so the wire format
    # hex-encodes them:
    #
    #   json = Confium::Composite::Signature.components_to_json(components)
    #   sig  = Confium::Composite::Signature.from_json(json)
    #   sig.verify(message)
    class Signature
      BINARY_FIELDS = %w[public_key signature].freeze

      def self.components_to_json(components)
        JSON.generate(components.map do |component|
          component.transform_values do |value|
            value.encoding == Encoding::ASCII_8BIT ? value.unpack1('H*') : value
          end
        end)
      end

      # Accepts either a bare JSON array of component Hashes or a
      # {"components": [...]} envelope, with public_key/signature
      # hex-encoded on the wire. Takes a JSON string or an
      # already-parsed Array/Hash.
      def self.from_json(json)
        data = json.is_a?(String) ? JSON.parse(json) : json
        components = data.is_a?(Hash) ? data['components'] : data
        unless components.is_a?(Array) && !components.empty?
          raise ArgumentError, 'expected a non-empty "components" array'
        end

        new(components.map { |c| decode_binary_fields(c) })
      end

      def self.decode_binary_fields(component)
        BINARY_FIELDS.each_with_object(component.dup) do |field, decoded|
          value = component.fetch(field)
          decoded[field] = [value].pack('H*') if value.is_a?(String)
        end
      end
      private_class_method :decode_binary_fields
    end
  end
end
