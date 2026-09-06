# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Confium::Transport::SignerClient do
  # The extension's Rust TcpListener bind fails on mingw (WSAENOTSOCK
  # 10038 / bind refusal) for noise:// and tcp:// alike — every fresh
  # port, deterministic. API-level specs run on Windows; the in-process
  # listener ceremonies are skipped there until the extension-side
  # Windows socket issue is fixed (tracked in the audit ledger).
  #
  # When skipping, attempt one real bind first and embed the OS error
  # in the skip reason — every Windows CI log then carries the exact
  # failure for the ledger investigation. ext/socket-smoke runs the
  # same crates outside Ruby on the same runner: if that is green
  # while this fails, the fault is the Ruby embedding environment.
  def windows?
    RUBY_PLATFORM =~ /mingw/
  end

  # Timeline bisect for the extension socket investigation: the same
  # diagnostic sequence runs at ext init, at suite start, and right
  # before each listener ceremony — the CI log then shows exactly
  # when each std net operation degrades (probe round g).
  def winsock_timeline(tag)
    Confium::Native.winsock_probe(tag)
  rescue StandardError => e
    warn "confium-winsock[#{tag}]: probe raised #{e.class}: #{e.message}"
  end

  def windows_listener_skip_reason
    return nil unless windows?

    begin
      Confium::Transport::CoordinatorServer.new("tcp://127.0.0.1:#{rand(49_152..64_999)}")
      nil # bind works after all — run the spec, do not skip
    rescue StandardError => e
      "Windows listener bind fails (see ledger): #{e.class}: #{e.message}"
    end
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
    winsock_timeline('pre-noise-ceremony') if windows?
    skip windows_listener_skip_reason if windows_listener_skip_reason
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
    winsock_timeline('pre-tcp-ceremony') if windows?
    skip windows_listener_skip_reason if windows_listener_skip_reason
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

RSpec.configure do |config|
  config.before(:suite) do
    if RUBY_PLATFORM =~ /mingw/
      begin
        Confium::Native.winsock_probe('before-suite')
      rescue StandardError => e
        warn "confium-winsock[before-suite]: probe raised #{e.class}: #{e.message}"
      end
    end
  end
end
