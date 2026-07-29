# frozen_string_literal: true

# Confium::OpenPGP — optional OpenPGP (RFC 9580) integration via ruby-rnp.
#
# Confium handles threshold cryptography + transparency logs. RNP handles
# standard OpenPGP (key management, signing, verification, encryption).
# Together they provide a complete crypto stack:
#
#   require "confium"
#   Confium::OpenPGP.verify(armor_signature, signed_data, public_key_armor)
#
# This module is a thin convenience wrapper. It lazily requires ruby-rnp
# on first use. If ruby-rnp is not installed, methods raise a clear error
# pointing to the install command:
#
#   gem install ruby-rnp
#
# Architecture: soft dependency pattern. The confium gem does NOT
# hard-depend on ruby-rnp. Users who need standard OpenPGP install it
# separately. The module detects its presence and either delegates or
# raises a helpful error.

module Confium
  module OpenPGP
    # Raised when ruby-rnp is not installed but an OpenPGP method is called.
    class NotInstalledError < Confium::Error
      def initialize
        super("ruby-rnp is not installed. Run: gem install ruby-rnp")
      end
    end

    @loaded = false
    @available = false

    class << self
      # True if ruby-rnp is installed and loadable.
      def available?
        return @available if @loaded

        @loaded = true
        begin
          require "rnp"
          @available = true
        rescue LoadError
          @available = false
        end
        @available
      end

      # Ensure ruby-rnp is loaded; raise if not installed.
      def ensure_available!
        return if available?

        raise NotInstalledError
      end

      # Verify an OpenPGP detached signature against signed data.
      #
      # @param signature_armor [String] Armored OpenPGP signature block.
      # @param signed_data [String] The data that was signed.
      # @param pubkey_armor [String] Armored public key block.
      # @return [Boolean] true if the signature verifies.
      # @raise [NotInstalledError] if ruby-rnp is not installed.
      def verify(signature_armor, signed_data, pubkey_armor)
        ensure_available!

        env = Rnp.new
        env.load_armored_pubkeys(pubkey_armor)

        input_sig = Rnp::Input.from_string(signature_armor)
        input_data = Rnp::Input.from_string(signed_data)
        output = Rnp::Output.to_null

        result = env.verify(input_sig, input_data, output)
        result[:success]
      end

      # Sign data with an OpenPGP private key.
      #
      # @param data [String] Data to sign.
      # @param key_armor [String] Armored private key block.
      # @param password [String] Key password (empty if none).
      # @return [String] Armored detached signature.
      # @raise [NotInstalledError] if ruby-rnp is not installed.
      def sign(data, key_armor, password: "")
        ensure_available!

        env = Rnp.new
        env.load_armored_keys(key_armor, password: password)

        signer = env.each_key.first
        raise Confium::NotFoundError, "no key found in armored input" unless signer

        input_data = Rnp::Input.from_string(data)
        output_sig = Rnp::Output.to_string

        op = Rnp::OpSign.new(env, input_data, output_sig)
        op.add_signer(signer)
        op.execute

        output_sig.string
      end

      # Generate an EdDSA OpenPGP keypair.
      #
      # @param userid [String] User ID for the key (e.g., "Alice <alice@example.com>").
      # @param password [String] Key protection password (empty for none).
      # @return [String] Armored keypair (secret + public).
      # @raise [NotInstalledError] if ruby-rnp is not installed.
      def generate_key(userid, password: "")
        ensure_available!

        env = Rnp.new
        keyid = env.generate_key(
          alg: "EDDSA",
          userid: userid,
          password: password.empty? ? nil : password
        )

        secret = Rnp::Output.to_string
        public_key = Rnp::Output.to_string
        env.export_secret_key(secret, keyid: keyid)
        env.export_public_key(public_key, keyid: keyid)
        "#{secret.string}\n#{public_key.string}"
      end

      # Encrypt data to one or more public keys.
      #
      # @param data [String] Data to encrypt.
      # @param pubkey_armor [String] Armored public key block.
      # @return [String] Armored encrypted message.
      # @raise [NotInstalledError] if ruby-rnp is not installed.
      def encrypt(data, pubkey_armor)
        ensure_available!

        env = Rnp.new
        env.load_armored_pubkeys(pubkey_armor)

        recipient = env.each_key.first
        raise Confium::NotFoundError, "no key found in armored input" unless recipient

        input_data = Rnp::Input.from_string(data)
        output = Rnp::Output.to_string

        op = Rnp::OpEncrypt.new(env, input_data, output)
        op.add_recipient(recipient)
        op.execute

        output.string
      end
    end
  end
end
