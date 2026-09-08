# frozen_string_literal: true

require 'spec_helper'
require 'socket'

# Wire constants pinned from python-opentimestamps (see the audit
# ledger's OTS wire-format reference).
OTS_FILE_MAGIC = [
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
  0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66,
  0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94
].pack('C*').freeze
OTS_PENDING_TAG = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e].pack('C*').freeze

RSpec.describe Confium::Transparency::OTS do
  def varuint(value)
    out = +''
    loop do
      byte = value & 0x7f
      value >>= 7
      out << (byte | (value.zero? ? 0 : 0x80))
      break if value.zero?
    end
    out
  end

  def pending_proof(uri)
    payload = varuint(uri.bytesize) + uri
    "#{OTS_FILE_MAGIC}\u0001\b\u0000#{OTS_PENDING_TAG}#{payload}"
  end

  # Read one full HTTP request (headers + Content-Length body).
  def read_http_request(client)
    request = +''
    loop do
      request << client.readpartial(1024)
      headers, rest = request.split("\r\n\r\n", 2)
      next if headers.nil? || rest.nil?

      length = headers[/Content-Length:\s*(\d+)/i, 1].to_i
      break if rest.bytesize >= length
    rescue EOFError
      break
    end
  end

  def with_calendar_stub(body:)
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    thread = Thread.new do
      client = server.accept
      read_http_request(client)
      client.write("HTTP/1.1 200 OK\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n")
      client.write(body)
      sleep 0.15
      client.close
      server.close
    end
    yield port
  ensure
    thread.join(5)
  end

  let(:digest) { Array.new(32) { |i| i + 1 }.pack('C*') }

  describe 'Client#stamp with a local calendar stub' do
    it 'returns a pending proof that verifies against the digest' do
      uri = 'http://127.0.0.1:9/cal'
      with_calendar_stub(body: pending_proof(uri)) do |port|
        client = described_class::Client.new(["http://127.0.0.1:#{port}"])
        proof = client.stamp(digest)
        expect(proof).to be_a(described_class::Proof)
        expect(proof.digest).to eq(digest)
        expect(proof.to_bytes.bytesize).to be > OTS_FILE_MAGIC.bytesize

        summary = proof.verify
        expect(summary['pending']).to eq([uri])
        expect(summary['bitcoin']).to eq([])
        expect(summary['anchored']).to be(false)
      end
    end

    it 'raises a typed error on a garbage response' do
      with_calendar_stub(body: 'not-an-ots-proof') do |port|
        client = described_class::Client.new(["http://127.0.0.1:#{port}"])
        expect { client.stamp(digest) }.to raise_error(StandardError)
      end
    end
  end

  describe 'offline behavior' do
    it 'raises rather than returning nil' do
      client = described_class::Client.new(['http://127.0.0.1:1'])
      expect { client.stamp(digest) }.to raise_error(IOError)
    end
  end

  describe 'Proof' do
    it 'rejects a digest that is not 32 bytes' do
      expect { described_class::Proof.new('short', pending_proof('x')) }
        .to raise_error(ArgumentError, /32/)
    end

    it 'raises ParseError on malformed proof bytes' do
      proof = described_class::Proof.new(digest, "\x00\x01garbage")
      expect { proof.verify }.to raise_error(Confium::Transparency::OTS::ParseError)
    end
  end

  describe 'module surface' do
    it 'keeps the default calendar pool and real client wiring' do
      expect(described_class::DEFAULT_CALENDARS.length).to be >= 3
      expect(described_class).to respond_to(:stamp, :verify, :upgrade)
    end

    it 'verifies proof bytes via the module function' do
      uri = 'https://bob.btc.calendar.opentimestamps.org'
      proof = described_class::Proof.new(digest, pending_proof(uri))
      summary = described_class.verify(proof)
      expect(summary['pending']).to eq([uri])
    end
  end
end
