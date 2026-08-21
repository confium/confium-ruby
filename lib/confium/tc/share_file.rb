# frozen_string_literal: true

require 'json'
require 'fileutils'

module Confium
  module TC
    # Filesystem-backed share persistence.
    #
    # Share blobs produced by `Confium::TC::Cmp20.keygen` /
    # `Confium::TC::Gg18.keygen` are 71-byte binary strings. This
    # class wraps them in a JSON envelope so they can be saved to
    # disk, transferred between hosts, and loaded back without
    # encoding ambiguity.
    #
    # The envelope format:
    #
    #     {
    #       "scheme":      "CMP20-ECDSA-P256",
    #       "threshold":   3,
    #       "party_count": 5,
    #       "public_key":  "<33-byte hex>",
    #       "shares":      ["<71-byte hex>", ...]
    #     }
    #
    # The format is identical to what the Python binding's
    # `confium.tc.ShareFile` produces, so shares saved from one
    # binding can be loaded by the other.
    class ShareFile
      attr_reader :scheme, :threshold, :party_count, :public_key, :shares

      def initialize(scheme:, threshold:, party_count:, public_key:, shares:)
        @scheme = scheme
        @threshold = threshold
        @party_count = party_count
        @public_key = public_key
        @shares = shares
      end

      # Load a ShareFile from a JSON file at `path`.
      def self.load(path)
        from_json(File.read(path))
      end

      # Parse a ShareFile from a JSON string.
      def self.from_json(json)
        d = JSON.parse(json)
        new(
          scheme: d.fetch('scheme'),
          threshold: d.fetch('threshold'),
          party_count: d.fetch('party_count'),
          public_key: [d.fetch('public_key')].pack('H*'),
          shares: d.fetch('shares').map { |h| [h].pack('H*') }
        )
      end

      # Save to `path` as JSON. Creates parent directories if missing.
      def save(path)
        FileUtils.mkdir_p(File.dirname(path))
        File.write(path, to_json)
        self
      end

      # Serialize to a JSON string.
      def to_json(*_args)
        JSON.generate(
          scheme: scheme,
          threshold: threshold,
          party_count: party_count,
          public_key: public_key.unpack1('H*'),
          shares: shares.map { |s| s.unpack1('H*') }
        )
      end

      # Build a ShareFile from a CMP20 / GG18 keygen result Hash.
      def self.from_keygen(scheme_name, keygen_result)
        new(
          scheme: scheme_name,
          threshold: nil, # not carried by the keygen Hash; caller knows
          party_count: keygen_result['shares'].length,
          public_key: keygen_result['public_key'],
          shares: keygen_result['shares']
        )
      end
    end
  end
end
