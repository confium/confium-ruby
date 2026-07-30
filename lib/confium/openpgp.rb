# frozen_string_literal: true

# Confium::OpenPGP — OpenPGP (RFC 9580) via bundled rnp-rs.
#
# The native extension provides _native_armor / _native_dearmor.
# This file adds the idiomatic Ruby wrappers with default args.
#
# Architecture: RNP is HARD-BUNDLED in the native extension. No
# external gem dependency. Users get OpenPGP armor encode/decode
# out of the box.

module Confium
  module OpenPGP
    class << self
      # ASCII-armor encode raw bytes.
      #
      # @param data [String] Binary data to encode.
      # @param type [String] Armor type — one of MESSAGE, PUBLIC_KEY,
      #   SECRET_KEY, SIGNATURE, CLEARTEXT. Defaults to MESSAGE.
      # @return [String] Armored ASCII string.
      def armor(data, type = MESSAGE)
        _native_armor(data, type)
      end

      # Decode ASCII-armored data to raw bytes.
      #
      # @param data [String] Armored ASCII string.
      # @return [String] Raw binary data.
      def dearmor(data)
        _native_dearmor(data)
      end
    end
  end
end
