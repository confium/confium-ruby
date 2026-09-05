# frozen_string_literal: true

require 'spec_helper'
require 'socket'

RSpec.describe Confium::Transport::SignerClient do
  # OS-assigned free port: a random low port can collide with real
  # listeners on CI runners (sshd on 22 etc.), and the noise handshake
  # blocks forever reading from a non-noise peer.
  def free_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server.close
    port
  end

  # Probe-then-rebind can transiently fail on Windows (WSAENOTSOCK on
  # immediate rebind, or an address still claimed); retry with a
  # fresh port instead of asserting on the first attempt.
  def start_server(scheme)
    attempts = 0
    begin
      attempts += 1
      port = free_port
      Confium::Transport::CoordinatorServer.new("#{scheme}://127.0.0.1:#{port}")
      port
    rescue IOError
      retry if attempts < 5
      raise
    end
  end

  it 'connects to a noise-served coordinator and registers' do
    port = start_server('noise')
    expect(port).to be_a(Integer)

    client = described_class.new("noise://127.0.0.1:#{port}")
    expect(client).to be_a(described_class)
    expect { client.register('signer-1', 'quorum-a') }.not_to raise_error

    session_id = client.create_session('quorum-a', 'CMP20', 'payload bytes', 2, 3)
    expect(session_id).to be_a(String)
    expect(session_id).not_to be_empty
  end

  it 'also works over plain tcp' do
    # The coordinator's registry TCP scheme is confium-net-tcp, linked
    # into the extension; a failed connect here means the scheme did
    # not resolve.
    port = start_server('tcp')
    client = described_class.new("tcp://127.0.0.1:#{port}")
    expect { client.register('signer-tcp', 'quorum-tcp') }.not_to raise_error
  end

  it 'raises on an unresolvable scheme' do
    expect { described_class.new('nosuch://127.0.0.1:1') }
      .to raise_error(StandardError, /nosuch/i)
  end
end
