# frozen_string_literal: true

# Audit log sink hierarchy.
#
# Sinks receive an audit record Hash for every signed event. The Rust
# extension fires events on every signing / verification / encryption
# op; the Ruby side routes them to the configured sink via
# {Confium::Audit.sink=}.
#
# Three reference sinks are shipped: {FileSink} (append-only file),
# {MemorySink} (in-memory, for testing), {StderrSink} (one-line JSON
# per record). Custom sinks can subclass {Sink} for HTTP / syslog /
# Kafka backends.

require 'json'
require 'time'

module Confium
  module Audit
    # Base class for audit sinks. Subclasses override {#write} and
    # optionally {#close}. The contract:
    #
    # - #write(record) — synchronously emit the record. Raise on
    #   failure; the exception propagates back through the caller.
    # - #close — flush and release resources. Safe to call multiple
    #   times.
    class Sink
      # Persist an audit record Hash. The Hash has these keys
      # (all Strings):
      #
      # - `"timestamp"`      — ISO8601 UTC, e.g. `"2026-07-30T22:00:00Z"`
      # - `"operation"`      — short slug like `"composite_sign"`
      # - `"actor"`          — optional String
      # - `"algorithm"`      — optional String
      # - `"payload_hash"`   — hex SHA-256 of the signed bytes
      # - `"result"`         — `"success"` or `"failure"`
      # - `"error"`          — optional String
      def write(_record)
        raise NotImplementedError, "#{self.class} must implement #write"
      end

      # Treat the Sink as a callable — delegates to {#write}. The Rust
      # extension's audit module fires events by calling `.call(record)`
      # on whatever is in `Confium::Audit.sink`, so this lets both
      # Proc-based and Object-based sinks work through the same
      # dispatch point.
      def call(record)
        write(record)
      end

      def close
        # default no-op
      end
    end

    # In-memory sink. Records are collected in `#records` and inspected
    # in specs. Implements `#clear` for resetting between tests.
    #
    # Includes Enumerable so callers can iterate, filter, and reduce
    # over recorded events directly:
    #
    #     sink.select { |r| r["operation"] == "composite_sign" }
    #     sink.count { |r| r["result"] == "failure" }
    #     sink.find { |r| r["actor"] == "director-1" }
    class MemorySink < Sink
      include Enumerable

      attr_reader :records

      def initialize
        # @type ivar @records: Array[untyped]
        @records = []
      end

      def write(record)
        @records << record
        self
      end

      def clear
        @records.clear
      end

      # Enumerable contract: yield each record in insertion order.
      def each(&)
        @records.each(&)
      end
    end

    # Stderr sink — emits each record as a one-line JSON object.
    # Suitable for development and CI; for production prefer
    # {FileSink} or a structured-logging sink.
    class StderrSink < Sink
      def initialize(io: $stderr)
        @io = io
      end

      def write(record)
        @io.puts(JSON.generate(record))
      end
    end

    # Append-only file sink. The path is opened in append mode; each
    # record is written as a single line followed by a newline.
    # Concurrent writes from multiple processes are NOT supported —
    # serialize audit traffic through this sink to a single writer for
    # multi-process deployments.
    class FileSink < Sink
      attr_reader :path

      def initialize(path)
        @path = path
        @io = File.open(path, 'a')
        @io.sync = true
      end

      def write(record)
        @io.puts(JSON.generate(record))
      end

      def close
        @io.close unless @io.closed?
      end
    end
  end
end

require_relative 'audit/otlp_sink'
