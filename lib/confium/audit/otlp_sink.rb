# frozen_string_literal: true

require 'net/http'
require 'json'
require 'time'

module Confium
  module Audit
    # Exports audit records to an OpenTelemetry Collector over
    # OTLP/HTTP JSON (the logs signal — an audit event is a log
    # record, not a span).
    #
    #   Confium::Audit.sink = Confium::Audit::OtlpSink.new(
    #     endpoint: 'http://localhost:4318/v1/logs',
    #     headers: { 'Authorization' => "Bearer #{token}" },
    #     service_name: 'confium-issuer'
    #   )
    #
    # Delivery is synchronous per record, retried with exponential
    # backoff (retries: attempts after the first, base doubled per
    # attempt). After the final failure the record is dropped with a
    # $stderr report — the audit core's policy: a telemetry outage
    # must never break signing. stdlib only.
    class OtlpSink < Sink
      DEFAULT_ENDPOINT = 'http://localhost:4318/v1/logs'
      SEVERITY = { 'success' => 9, 'failure' => 17, 'error' => 17 }.freeze # INFO / ERROR

      def initialize(endpoint: DEFAULT_ENDPOINT, headers: {}, service_name: 'confium', timeout: 5,
                     retries: 2, retry_base: 0.1)
        super()
        @uri = URI.parse(endpoint)
        @headers = headers
        @service_name = service_name
        @timeout = timeout
        @retries = retries
        @retry_base = retry_base
        @dropped = 0
      end

      # Records dropped after failed delivery (diagnostic only).
      attr_reader :dropped

      def write(record)
        payload = envelope(record)
        deliver(JSON.generate(payload))
      rescue StandardError => e
        @dropped += 1
        warn "confium: OTLP delivery failed, audit record dropped (##{@dropped}): #{e.class}: #{e.message}"
      end

      def close; end

      private

      # Attempts grow the backoff: retry_base * 2**attempt. When
      # retry_base is 0 (specs) retries run without delay.
      def deliver(body)
        (@retries + 1).times do |attempt|
          sleep(@retry_base * (2**attempt)) if attempt.positive? && @retry_base.positive?

          response = Net::HTTP.post(@uri, body, headers.merge('Content-Type' => 'application/json'))
          return response if response.is_a?(Net::HTTPSuccess)

          raise "collector responded #{response.code}" if attempt == @retries
        end
      end

      def headers
        { 'User-Agent' => "confium-otlp-sink #{Confium::VERSION}" }.merge(@headers)
      end

      # OTLP/JSON logs request: one resource, one scope, one record.
      def envelope(record)
        {
          'resourceLogs' => [
            {
              'resource' => {
                'attributes' => [
                  { 'key' => 'service.name', 'value' => { 'stringValue' => @service_name } },
                  { 'key' => 'telemetry.sdk.name', 'value' => { 'stringValue' => 'confium' } },
                  { 'key' => 'telemetry.sdk.version', 'value' => { 'stringValue' => Confium::VERSION } }
                ]
              },
              'scopeLogs' => [
                {
                  'scope' => { 'name' => 'confium.audit' },
                  'logRecords' => [log_record(record)]
                }
              ]
            }
          ]
        }
      end

      def log_record(record)
        {
          'timeUnixNano' => (parse_time(record['timestamp']) * 1_000_000_000).to_i.to_s,
          'severityNumber' => SEVERITY.fetch(record['result'], 9),
          'severityText' => record['result'] == 'success' ? 'INFO' : 'ERROR',
          'body' => { 'stringValue' => "#{record['operation']} #{record['result']}".strip },
          'attributes' => attributes_for(record)
        }
      end

      def attributes_for(record)
        record.except('timestamp').map do |key, value|
          { 'key' => key, 'value' => { 'stringValue' => value.to_s } }
        end
      end

      def parse_time(timestamp)
        return Time.now.to_f unless timestamp.is_a?(String)

        Time.parse(timestamp).to_f
      rescue ArgumentError
        Time.now.to_f
      end
    end
  end
end
