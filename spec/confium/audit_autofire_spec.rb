# frozen_string_literal: true

require 'confium'

RSpec.describe 'Audit auto-fire from signing ops' do
  let(:sink) { Confium::Audit::MemorySink.new }

  before { Confium::Audit.sink = sink }
  after  { Confium::Audit.sink = nil }

  it 'fires an event on successful Confium::Composite.sign_ed25519' do
    kp = Confium::Composite.generate_ed25519_keypair
    Confium::Composite.sign_ed25519(kp['private_key'], 'ed25519 audit')

    event = sink.find { |r| r['operation'] == 'composite_sign_ed25519' }
    expect(event).not_to be_nil
    expect(event['result']).to eq('success')
    expect(event['algorithm']).to eq('Ed25519')
    expect(event['payload_hash']).to match(/\A[0-9a-f]{64}\z/)
    expect(event['timestamp']).to match(/\A\d{4}-\d{2}-\d{2}T/)
  end

  it 'fires an event on successful Confium::Composite.sign_p256' do
    kp = Confium::TC::FrostP256.generate_keypair
    Confium::Composite.sign_p256(kp['private_key'], 'p256 audit')

    event = sink.find { |r| r['operation'] == 'composite_sign_p256' }
    expect(event).not_to be_nil
    expect(event['result']).to eq('success')
    expect(event['algorithm']).to eq('ECDSA-P256')
  end

  it 'fires an event on successful Confium::TC::FrostP256.sign' do
    kp = Confium::TC::FrostP256.generate_keypair
    Confium::TC::FrostP256.sign(kp['private_key'], 'frost audit')

    event = sink.find { |r| r['operation'] == 'tc_frost_p256_sign' }
    expect(event).not_to be_nil
    expect(event['result']).to eq('success')
    expect(event['algorithm']).to eq('FROST-P256')
  end

  it 'fires an event on successful Confium::TC::Cmp20.keygen' do
    Confium::TC::Cmp20.keygen(2, 3)

    event = sink.find { |r| r['operation'] == 'tc_cmp20_keygen' }
    expect(event).not_to be_nil
    expect(event['result']).to eq('success')
    expect(event['algorithm']).to eq('CMP20-ECDSA-P256')
    # No payload hash for keygen — there's no input message to hash.
    expect(event['payload_hash']).to eq('')
  end

  it 'fires an event on successful Confium::TC::Cmp20.sign' do
    kg = Confium::TC::Cmp20.keygen(2, 3)
    sink.clear # ignore keygen event
    Confium::TC::Cmp20.sign(kg['shares'].first(2), 2, 'cmp20 audit')

    event = sink.find { |r| r['operation'] == 'tc_cmp20_sign' }
    expect(event).not_to be_nil
    expect(event['result']).to eq('success')
    expect(event['payload_hash']).to match(/\A[0-9a-f]{64}\z/)
  end

  it 'fires an event on successful Confium::TC::Gg18.sign' do
    kg = Confium::TC::Gg18.keygen(2, 3)
    sink.clear
    Confium::TC::Gg18.sign(kg['shares'].first(2), 2, 'gg18 audit')

    event = sink.find { |r| r['operation'] == 'tc_gg18_sign' }
    expect(event).not_to be_nil
    expect(event['result']).to eq('success')
    expect(event['algorithm']).to eq('GG18-ECDSA-P256')
  end

  it 'fires a failure event when threshold is unmet' do
    kg = Confium::TC::Cmp20.keygen(3, 5)
    sink.clear
    expect do
      Confium::TC::Cmp20.sign(kg['shares'].first(2), 3, 'msg')
    end.to raise_error(Confium::ThresholdError)

    event = sink.find { |r| r['operation'] == 'tc_cmp20_sign' }
    expect(event).not_to be_nil
    expect(event['result']).to eq('failure')
    expect(event['error']).to match(/Threshold/)
  end

  it 'is silent when no sink is configured' do
    Confium::Audit.sink = nil
    # Should not raise — audit is best-effort.
    expect do
      kp = Confium::Composite.generate_ed25519_keypair
      Confium::Composite.sign_ed25519(kp['private_key'], 'no-sink')
    end.not_to raise_error
  end

  it 'audit failures do not propagate to the signing op' do
    # Sink that raises on every call.
    broken_sink = Class.new do
      def call(_record)
        raise 'broken sink'
      end
    end.new
    Confium::Audit.sink = broken_sink

    kp = Confium::Composite.generate_ed25519_keypair
    # The signing op should still succeed despite the sink failing.
    expect do
      Confium::Composite.sign_ed25519(kp['private_key'], 'broken-sink test')
    end.not_to raise_error
  end
end
