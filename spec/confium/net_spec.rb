# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Confium::Net::SignerClient do
  let(:port) { rand(1..20_000) }

  it 'connects to a noise-served coordinator and registers' do
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
    Confium::Net::CoordinatorServer.new("tcp://127.0.0.1:#{port + 1}")
    # The coordinator's registry TCP scheme is confium-net-tcp, linked
    # transitively through the coordinator; a failed connect here means
    # the scheme did not resolve.
    client = described_class.new("tcp://127.0.0.1:#{port + 1}")
    expect { client.register('signer-tcp', 'quorum-tcp') }.not_to raise_error
  end

  it 'raises on an unresolvable scheme' do
    expect { described_class.new('nosuch://127.0.0.1:1') }
      .to raise_error(StandardError, /nosuch/i)
  end
end
