# frozen_string_literal: true

# {Confium::Crypto} is the registry namespace for Confium's cryptographic
# interfaces.
#
# Mirroring the Rust plugin-interface registry (TODO #02), each Ruby
# interface module (Digest, and future Cipher, AEAD, KDF, RNG, Signature,
# KEM, ...) registers itself here on load rather than being enumerated in
# a central case statement. This keeps the registry open for extension
# (OCP) and makes the set of available interfaces a single source of
# truth.
#
# Example:
#
#   module Confium
#     module Digest
#       Confium::Crypto.register(:hash, self)
#     end
#   end
#
#   Confium::Crypto.lookup(:hash)  # => Confium::Digest
module Confium
  module Crypto
    @interfaces = {}

    class << self
      # Register an interface +klass+ under the symbolic +name+. Adding a
      # new interface is a one-line registration; no central switch needs
      # editing.
      def register(name, klass)
        @interfaces[name] = klass
        klass
      end

      # Resolve a registered interface by +name+. Raises ArgumentError if
      # nothing has been registered under that name.
      def lookup(name)
        @interfaces.fetch(name) do
          raise ArgumentError, "unknown interface #{name.inspect}"
        end
      end

      # Enumerate the names of every registered interface. Primarily for
      # introspection and tooling.
      def interfaces
        @interfaces.keys.dup
      end
    end
  end
end
