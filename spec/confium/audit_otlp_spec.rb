# frozen_string_literal: true

require 'confium'
require 'json'
require 'socket'

# Drives OtlpSink against a real local HTTP collector stub: asserts
# the OTLP/HTTP JSON envelope the collector would receive.
RSpec.describe Confium::Audit::OtlpSink do
  let(:collector) do
    server = TCPServer.new('127.0.0.1', 0)
    port = server.addr[1]
    requests = Queue.new
    Thread.new do
      loop do
        client = server.accept
        request = +''
        headers = {}
        until (line = client.readline).strip.empty?
          request << line
          key, value = line.split(':', 2)
          headers[key.strip.downcase] = value.strip if value
        end
        body = client.read(headers['content-length'].to_i)
        requests << { 'headers' => headers, 'body' => body }
        client.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        client.close
      end
    rescue IOError
      break
    end
    Struct.new(:port, :requests, :stop).new(port, requests, -> { server.close })
  end

  let(:record) do
    {
      'operation' => 'composite_sign',
      'result' => 'success',
      'algorithm' => 'Ed25519+P256',
      'payload_hash' => 'deadbeef',
      'timestamp' => '2026-08-24T12:00:00Z'
    }
  end

  after { collector.stop.call }

  def sink_for(port)
    described_class.new(endpoint: "http://127.0.0.1:#{port}/v1/logs", service_name: 'spec-service')
  end

  it 'posts a valid OTLP/HTTP JSON logs envelope' do
    sink_for(collector.port).write(record)
    request = collector.requests.pop
    envelope = JSON.parse(request['body'])

    expect(request['headers']['content-type']).to eq('application/json')
    resource_logs = envelope.fetch('resourceLogs').first
    attributes = resource_logs.fetch('resource').fetch('attributes')
    expect(attributes.find { |a| a['key'] == 'service.name' }['value']['stringValue']).to eq('spec-service')

    log = resource_logs.fetch('scopeLogs').first.fetch('logRecords').first
    expect(log['body']['stringValue']).to eq('composite_sign success')
    expect(log['severityText']).to eq('INFO')
    expect(log['timeUnixNano']).to eq("#{Time.parse('2026-08-24T12:00:00Z').to_i}000000000")

    record_attrs = log.fetch('attributes').to_h { |a| [a['key'], a['value']['stringValue']] }
    expect(record_attrs['operation']).to eq('composite_sign')
    expect(record_attrs['algorithm']).to eq('Ed25519+P256')
    expect(record_attrs).not_to have_key('timestamp')
  end

  it 'maps failure results to ERROR severity' do
    sink_for(collector.port).write(record.merge('result' => 'failure'))
    envelope = JSON.parse(collector.requests.pop['body'])
    log = envelope['resourceLogs'].first['scopeLogs'].first['logRecords'].first
    expect(log['severityText']).to eq('ERROR')
    expect(log['severityNumber']).to eq(17)
  end

  it 'drops the record and keeps going when the collector is unreachable' do
    sink = described_class.new(endpoint: 'http://127.0.0.1:1/v1/logs', timeout: 1)
    expect { sink.write(record) }.to output(/OTLP delivery failed/).to_stderr
    expect(sink.dropped).to eq(1)
  end

  it 'sends custom headers (collector auth)' do
    sink = described_class.new(
      endpoint: "http://127.0.0.1:#{collector.port}/v1/logs",
      headers: { 'Authorization' => 'Bearer token' }
    )
    sink.write(record)
    request = collector.requests.pop
    expect(request['headers']['authorization']).to eq('Bearer token')
  end
end
