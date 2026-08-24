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

      # Serialize the components this instance was built from, in the
      # canonical wire format. Instances remember their source: built
      # from components, or from a JSON document (which is emitted
      # verbatim when it was canonical).
      def to_json(*_args)
        cached = @confium_components_json
        return cached if cached

        components = @confium_components or
          raise Confium::Error, 'Signature was not built with component data; use Signature.new or from_json'
        Signature.components_to_json(components)
      end

      class << self
        # magnus exposes the constructor as a class-level `new`;
        # capture it before this reopen shadows it (plain `super`
        # falls through to Class#new instead).
        alias __native_new new

        def new(*args)
          sig = __native_new(*args)
          sig.instance_variable_set(:@confium_components, args.first) if args.first.is_a?(Array)
          sig
        end
      end

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

        sig = new(components.map { |c| decode_binary_fields(c) })
        sig.instance_variable_set(:@confium_components, components)
        sig.instance_variable_set(:@confium_components_json, canonical_json(json, data))
        sig
      end

      # The canonical wire form of whatever the caller handed us: a
      # String passes through untouched; parsed structures are
      # re-generated from their components array.
      def self.canonical_json(json, data)
        return json if json.is_a?(String)

        JSON.generate(data.is_a?(Hash) ? data['components'] : data)
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
