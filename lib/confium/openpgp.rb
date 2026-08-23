# frozen_string_literal: true

module Confium
  # OpenPGP ASCII armor (RFC 9580 §6) — Radix-64 framing with a
  # CRC-24 checksum, implemented in pure Ruby.
  #
  # This replaced the earlier native wrapper around librnp, which
  # pulled a full vendored Botan/json-c C/C++ build into every
  # install just to do armor framing. The wire format is unchanged;
  # spec/fixtures/openpgp_armor_vectors.json holds differential
  # vectors captured from the native implementation.
  module OpenPGP
    MESSAGE = 'message'
    PUBLIC_KEY = 'public key'
    SECRET_KEY = 'secret key'
    SIGNATURE = 'signature'
    CLEARTEXT = 'cleartext signed message'

    LABELS = {
      nil => 'MESSAGE',
      MESSAGE => 'MESSAGE',
      'public key' => 'PUBLIC KEY BLOCK',
      SECRET_KEY => 'PRIVATE KEY BLOCK',
      'private key' => 'PRIVATE KEY BLOCK',
      SIGNATURE => 'SIGNATURE',
      # Raw bytes cannot form a cleartext-signed message (that
      # requires a signature packet); armor them as a plain message.
      CLEARTEXT => 'MESSAGE',
      'cleartext' => 'MESSAGE'
    }.freeze

    CRC_POLY = 0x1864CFB
    CRC_INIT = 0xB704CE
    B64_CHARS = [('A'..'Z').to_a, ('a'..'z').to_a, ('0'..'9').to_a, %w[+ /]].flatten.freeze
    CRC_TABLE = (0..255).map do |i|
      c = i << 16
      8.times do
        c = c.nobits?(0x800_000) ? c << 1 : ((c << 1) ^ CRC_POLY)
        c &= 0xFFFFFF
      end
      c
    end.freeze

    private_constant :LABELS, :CRC_POLY, :CRC_INIT, :B64_CHARS, :CRC_TABLE

    class << self
      # ASCII-armor encode raw bytes. Output uses CRLF line endings
      # and 76-character data lines, byte-for-byte matching the
      # earlier native (rnp) implementation.
      #
      # @param data [String] Binary data to encode.
      # @param type [String] One of MESSAGE, PUBLIC_KEY, SECRET_KEY,
      #   SIGNATURE, CLEARTEXT (armored as a plain message). Defaults
      #   to MESSAGE.
      # @return [String] Armored ASCII string.
      # @raise [ArgumentError] if +type+ is not a known armor type.
      def armor(data, type = MESSAGE)
        label = LABELS[type]
        raise ArgumentError, "unknown armor type: #{type.inspect}" unless label

        bytes = data.to_s.b
        b64 = [bytes].pack('m0')
        lines = b64.scan(/.{1,76}/)
        <<~ARMOR.gsub("\n", "\r\n")
          -----BEGIN PGP #{label}-----

          #{lines.join("\n")}
          =#{crc24_armor(bytes)}
          -----END PGP #{label}-----
        ARMOR
      end

      # Decode ASCII-armored data to raw bytes. Accepts LF or CRLF
      # line endings, arbitrary line widths, and Armor Headers
      # (Comment:, Version:, ...) between the BEGIN line and the
      # blank line. The CRC-24 checksum line is verified when
      # present.
      #
      # @param data [String] Armored ASCII string.
      # @return [String] Raw binary data (ASCII-8BIT).
      # @raise [Confium::ParseError] on missing delimiters, non-base64
      #   content, or a CRC mismatch.
      def dearmor(data)
        b64, crc_line = extract_body(data.to_s)
        # @type var bytes: String
        bytes = b64.unpack1('m0')
        return ''.b if crc_line == crc24_armor(''.b) && b64.empty?

        raise ParseError, 'armor CRC-24 checksum mismatch' if crc_line && crc24_armor(bytes) != crc_line.to_s

        bytes
      end

      private

      # Locate the armored block, skip the BEGIN line and any Armor
      # Headers, and split the remaining lines into the joined
      # Radix-64 data and the checksum line (if present).
      def extract_body(text)
        lines = block_lines(text)
        b64, crc_line = collect_data(lines)
        raise ParseError, 'armored block has no data' if b64.empty? && crc_line.nil?

        [b64, crc_line]
      end

      # The lines of the armored block between BEGIN and END, with
      # the BEGIN line and any Armor Headers removed.
      def block_lines(text)
        slice = block_slice(text.gsub("\r\n", "\n"))
        lines = slice.split("\n")
        lines.shift # BEGIN
        lines.shift while lines.first&.match?(/^\s|^[A-Za-z0-9-]+: /)
        lines.shift if lines.first == ''
        lines
      end

      # The text between the BEGIN and END delimiter lines.
      def block_slice(normalized)
        begin_line = normalized.index(/^-----BEGIN PGP [A-Z ]+-----$/)
        raise ParseError, 'not an ASCII-armored block (no BEGIN line)' unless begin_line

        end_match = normalized.match(/^-----END PGP [A-Z ]+-----$/)
        raise ParseError, 'not an ASCII-armored block (no END line)' unless end_match

        normalized[begin_line...end_match.begin(0)].to_s
      end

      def collect_data(lines)
        b64 = +''
        crc_line = nil
        lines.each do |line|
          next if line.empty?

          if line.start_with?('=')
            crc_line = line[1..]
          elsif line.match?(%r{\A[A-Za-z0-9+/]+={0,2}\z})
            b64 << line
          else
            raise ParseError, "invalid armor data line: #{line[0, 20].inspect}"
          end
        end
        [b64, crc_line]
      end

      # CRC-24 (RFC 9580 §6.1), encoded as the four Radix-64
      # characters of the 24-bit value as three big-endian bytes.
      def crc24_armor(bytes)
        crc = CRC_INIT
        bytes.each_byte { |b| crc = ((crc << 8) & 0xFFFFFF) ^ CRC_TABLE[((crc >> 16) ^ b) & 0xFF] }
        three_bytes = [crc >> 16, (crc >> 8) & 0xFF, crc & 0xFF].pack('C3')
        [three_bytes].pack('m0')
      end
    end
  end
end
