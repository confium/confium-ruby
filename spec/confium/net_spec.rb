# frozen_string_literal: true

require 'spec_helper'
require 'socket'

RSpec.describe Confium::Net::SignerClient do
  # OS-assigned free port: a random low port can collide with real
  # listeners on CI runners (sshd on 22 etc.), and the noise handshake
  # blocks forever reading from a non-noise peer.
  def free_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    server.close
    port
  end

  it 'connects to a noise-served coordinator and registers' do
    port = free_port
    server = Confium::Net::CoordinatorServer.new("noise://127.0.0.1:#{port}")
    expect(server).to be_a(Confium::Net::CoordinatorServer)

    client = described_class.new("noise://127.0.0.1:#{port}")
    expect(client).to be_a(described_class)
    expect { client.register('signer-1', 'quorum-a') }.not_to raise_error

    session_id = client.create_session('quorum-a', 'CMP20', 'payload bytes', 2, 3)
    expect(session_id).to be_a(String)
    expect(session_id).not_to be_empty
  end

  it 'also works over plain tcp' do
    port = free_port
    # The coordinator's registry TCP scheme is confium-net-tcp, linked
    # into the extension; a failed connect here means the scheme did
    # not resolve.
    Confium::Net::CoordinatorServer.new("tcp://127.0.0.1:#{port}")
    client = described_class.new("tcp://127.0.0.1:#{port}")
    expect { client.register('signer-tcp', 'quorum-tcp') }.not_to raise_error
  end

  it 'raises on an unresolvable scheme' do
    expect { described_class.new('nosuch://127.0.0.1:1') }
      .to raise_error(StandardError, /nosuch/i)
  end
end
