# frozen_string_literal: true

require 'confium'
require 'tmpdir'

RSpec.describe Confium::Audit do
  after { Confium::Audit.sink = nil }

  describe '.sink= / .sink' do
    it 'returns nil by default' do
      expect(described_class.sink).to be_nil
    end

    it 'stores the sink globally' do
      sink = Confium::Audit::MemorySink.new
      described_class.sink = sink
      expect(described_class.sink).to be(sink)
    end
  end

  describe '.enabled?' do
    it 'is false when no sink is set' do
      expect(described_class.enabled?).to be(false)
    end

    it 'is true when a sink is set' do
      described_class.sink = Confium::Audit::MemorySink.new
      expect(described_class.enabled?).to be(true)
    end
  end

  describe Confium::Audit::MemorySink do
    it 'starts empty' do
      sink = described_class.new
      expect(sink.records).to eq([])
    end

    it 'appends records via #write' do
      sink = described_class.new
      sink.write('timestamp' => '2026-01-01T00:00:00Z', 'operation' => 'test')
      expect(sink.records.length).to eq(1)
      expect(sink.records.first['operation']).to eq('test')
    end

    it 'clears records on #clear' do
      sink = described_class.new
      sink.write('operation' => 'test')
      sink.clear
      expect(sink.records).to be_empty
    end
  end

  describe Confium::Audit::FileSink do
    it 'appends one JSON record per line' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'audit.log')
        sink = described_class.new(path)
        sink.write('timestamp' => '2026-01-01T00:00:00Z', 'operation' => 'a')
        sink.write('timestamp' => '2026-01-02T00:00:00Z', 'operation' => 'b')
        sink.close
        lines = File.read(path).lines
        expect(lines.length).to eq(2)
        expect(JSON.parse(lines[0])['operation']).to eq('a')
        expect(JSON.parse(lines[1])['operation']).to eq('b')
      end
    end

    it 'opens in append mode so existing records survive' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'audit.log')
        File.write(path, "{\"operation\":\"prior\"}\n")
        sink = described_class.new(path)
        sink.write('operation' => 'new')
        sink.close
        lines = File.read(path).lines
        expect(lines.length).to eq(2)
        expect(JSON.parse(lines[0])['operation']).to eq('prior')
        expect(JSON.parse(lines[1])['operation']).to eq('new')
      end
    end

    it 'is idempotent on close' do
      Dir.mktmpdir do |dir|
        sink = described_class.new(File.join(dir, 'audit.log'))
        sink.close
        expect { sink.close }.not_to raise_error
      end
    end
  end

  describe '.record routing' do
    it 'delivers records to a configured MemorySink' do
      sink = Confium::Audit::MemorySink.new
      described_class.sink = sink
      described_class.record(
        'composite_sign',
        '0123456789abcdef',
        'success',
        nil,
        'Ed25519+P256',
        nil
      )
      expect(sink.records.length).to eq(1)
      record = sink.records.first
      expect(record['operation']).to eq('composite_sign')
      expect(record['result']).to eq('success')
      expect(record['algorithm']).to eq('Ed25519+P256')
      expect(record['payload_hash']).to eq('0123456789abcdef')
      expect(record['timestamp']).to match(/\A\d{4}-\d{2}-\d{2}T/)
    end

    it 'is a no-op when no sink is set' do
      expect do
        described_class.record('noop_op', 'deadbeef', 'success', nil, nil, nil)
      end.not_to raise_error
    end
  end
end
