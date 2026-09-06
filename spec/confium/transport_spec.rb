# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Confium::Transport::SignerClient do
  # The extension's Rust TcpListener bind fails on mingw (WSAENOTSOCK
  # 10038 / bind refusal) for noise:// and tcp:// alike — every fresh
  # port, deterministic. API-level specs run on Windows; the in-process
  # listener ceremonies are skipped there until the extension-side
  # Windows socket issue is fixed (tracked in the audit ledger).
  def windows?
    RUBY_PLATFORM =~ /mingw/
  end

  # Random ephemeral-range port with bind retry. NOT probe-then-rebind:
  # Windows deterministically refuses to rebind a just-closed probe
  # socket (std does not set SO_REUSEADDR there), and low random ports
  # can collide with real CI listeners (sshd) whose non-noise response
  # stalls the handshake until the 10s deadline.
  def start_server(scheme)
    attempts = 0
    begin
      attempts += 1
      port = rand(49_152..64_999)
      Confium::Transport::CoordinatorServer.new("#{scheme}://127.0.0.1:#{port}")
      port
    rescue IOError
      retry if attempts < 5
      raise
    end
  end

  it 'connects to a noise-served coordinator and registers' do
    skip 'extension listener bind fails on Windows (see ledger)' if windows?
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
    skip 'extension listener bind fails on Windows (see ledger)' if windows?
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
