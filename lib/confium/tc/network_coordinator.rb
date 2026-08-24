# frozen_string_literal: true

require 'json'
require 'socket'
require_relative 'coordinator'

module Confium
  module TC
    # Networked threshold-signing coordinator service.
    #
    # Wraps Confium::TC::Coordinator (real CMP20/GG18 combine) behind
    # a TCP socket so signers on separate machines submit commitments
    # and shares from their own processes:
    #
    #   service = Confium::TC::NetworkCoordinator.new(quorum_id: 'root')
    #   service.start                       # binds 127.0.0.1:<ephemeral>
    #   client = Confium::TC::SignerClient.new(port: service.port)
    #   sid = client.create_session(message: data, threshold: 3)
    #   client.submit_share(sid, 'signer-1', share_blob)
    #   client.aggregate(sid)               # => 64-byte signature
    #
    # Protocol: one JSON object per line (NDJSON); binary fields are
    # hex-encoded. Unknown operations and Coordinator errors come
    # back as {"error": ..., "message": ...} lines.
    #
    # Transport security: none yet — plain TCP intended for loopback
    # or private networks. The upstream noise-transport session
    # protocol replaces this wholesale (see
    # TODO.full/01-multi-host-threshold-signing.md).
    class NetworkCoordinator
      HANDLERS = {
        'create' => lambda do |coord, req|
          session_id = coord.create_session(
            message: [req.fetch('message_hex')].pack('H*'),
            threshold: req.fetch('threshold'),
            scheme: req['scheme'] || 'CMP20-ECDSA-P256'
          )
          { 'session_id' => session_id }
        end,
        'commitment' => lambda do |coord, req|
          session_id = req.fetch('session_id')
          coord.submit_commitment(
            session_id, req.fetch('signer_id'),
            [req.fetch('bytes_hex')].pack('H*')
          )
          { 'ok' => true, 'state' => coord.session_state(session_id).to_s }
        end,
        'share' => lambda do |coord, req|
          coord.submit_share(
            req.fetch('session_id'), req.fetch('signer_id'),
            [req.fetch('bytes_hex')].pack('H*')
          )
          { 'ok' => true }
        end,
        'aggregate' => lambda do |coord, req|
          signature = coord.aggregate(req.fetch('session_id'))
          { 'signature_hex' => signature.unpack1('H*') }
        end
      }.freeze

      class RequestError < StandardError; end

      attr_reader :quorum_id, :port

      def initialize(quorum_id:, host: '127.0.0.1', port: 0, coordinator: nil)
        @quorum_id = quorum_id
        @host = host
        @port = port
        @coordinator = coordinator || Coordinator.new(quorum_id: quorum_id)
        @server = nil
        @accept_thread = nil
        @mutex = Mutex.new
      end

      def start
        raise 'already started' if @server

        # RBS socket lib lacks the (host, port) overload for new
        @server = TCPServer.new(@host.to_s, @port) # steep:ignore
        @port = @server.addr[1]
        @accept_thread = Thread.new { accept_loop }
        self
      end

      def stop
        return unless @server

        server = @server
        @server = nil
        server.close
        @accept_thread&.join(5)
        nil
      end

      def running?
        !@server.nil?
      end

      private

      def accept_loop
        loop do
          server = @server
          break unless server

          begin
            socket = server.accept
          rescue IOError, Errno::EBADF, Errno::EINVAL
            break # listener closed by #stop
          end
          Thread.new(socket) { |conn| serve(conn) }
        end
      end

      def serve(socket)
        socket.each_line do |line|
          request = JSON.parse(line)
          response = @mutex.synchronize { dispatch(request) }
          socket.write("#{JSON.generate(response)}\n")
        end
      rescue JSON::ParserError => e
        write_error(socket, 'RequestError', "malformed JSON: #{e.message}")
      rescue StandardError => e
        write_error(socket, e.class.name, e.message)
      ensure
        socket.close
      end

      def dispatch(request)
        op = request['op'] or raise RequestError, 'missing "op"'
        handler = HANDLERS[op] or raise RequestError, "unknown op: #{op}"

        handler.call(@coordinator, request)
      end

      def write_error(socket, klass, message)
        socket.write("#{JSON.generate({ 'error' => klass, 'message' => message })}\n")
      rescue IOError
        nil
      end
    end

    # Client side for NetworkCoordinator. One instance per signer
    # process; each call opens its own connection, so signers never
    # share state.
    class SignerClient
      class RemoteError < StandardError
        attr_reader :remote_class

        def initialize(remote_class, message)
          @remote_class = remote_class
          super("#{remote_class}: #{message}")
        end
      end

      def initialize(port:, host: '127.0.0.1')
        @host = host
        @port = port
      end

      def create_session(message:, threshold:, scheme: 'CMP20-ECDSA-P256')
        response = call(
          'op' => 'create',
          'message_hex' => message.to_s.unpack1('H*'),
          'threshold' => threshold,
          'scheme' => scheme
        )
        response.fetch('session_id')
      end

      def submit_commitment(session_id, signer_id, commitment_bytes)
        call(
          'op' => 'commitment',
          'session_id' => session_id,
          'signer_id' => signer_id,
          'bytes_hex' => commitment_bytes.unpack1('H*')
        ).fetch('ok')
      end

      def submit_share(session_id, signer_id, share_bytes)
        call(
          'op' => 'share',
          'session_id' => session_id,
          'signer_id' => signer_id,
          'bytes_hex' => share_bytes.unpack1('H*')
        ).fetch('ok')
      end

      def aggregate(session_id)
        response = call('op' => 'aggregate', 'session_id' => session_id)
        [response.fetch('signature_hex')].pack('H*')
      end

      private

      def call(request)
        TCPSocket.open(@host, @port) do |socket|
          socket.write("#{JSON.generate(request)}\n")
          line = socket.readline
          response = JSON.parse(line)
          raise RemoteError.new(response['error'], response['message']) if response['error']

          response
        end
      end
    end
  end
end
