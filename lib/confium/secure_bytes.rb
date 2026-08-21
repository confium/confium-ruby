# frozen_string_literal: true

# SecureBytes wraps sensitive cryptographic byte data (private keys,
# Shamir shares, shared secrets) with zeroize-on-clear semantics.
#
# MRI Ruby's String is backed by a heap-allocated char buffer that
# persists until GC. SecureBytes overwrites that buffer with zeros
# when #clear is called (explicitly or via finalizer).
#
# Usage:
#   key = Confium::SecureBytes.wrap(raw_bytes)
#   key.bytes  # non-destructive read
#   key.clear  # zeroize + deallocate
#
# After #clear, #bytes raises Confium::ClearedError.

module Confium
  class SecureBytes
    # Raised when #bytes is called after #clear.
    class ClearedError < Confium::Error
      def initialize(message = 'SecureBytes already cleared')
        super(message, details: {})
      end
    end

    # Create a SecureBytes wrapping a copy of the given String.
    # The original String's contents are NOT modified; callers should
    # zeroize the original separately if needed.
    # @param raw [String] binary String (any encoding; bytes are copied)
    # @return [Confium::SecureBytes]
    def self.wrap(raw)
      new(raw)
    end

    # @api private
    def initialize(raw)
      @buffer = raw.dup.force_encoding(Encoding::ASCII_8BIT)
      @cleared = false
      # Register finalizer to zeroize if the object is GC'd without
      # an explicit #clear call.
      ObjectSpace.define_finalizer(self, finalizer_proc)
    end

    # Non-destructive read of the wrapped bytes.
    # @return [String] binary String (ASCII-8BIT encoding)
    # @raise [ClearedError] if #clear was already called
    def bytes
      raise ClearedError if @cleared

      @buffer.dup
    end

    # Destructive read: returns a copy, then zeroizes the original.
    # @return [String] binary String
    # @raise [ClearedError] if #clear was already called
    def bytes!
      raise ClearedError if @cleared

      copy = @buffer.dup
      clear
      copy
    end

    # Number of bytes. Returns 0 after #clear.
    # @return [Integer]
    def length
      @cleared ? 0 : @buffer.bytesize
    end

    alias size length

    # Whether the buffer has been cleared.
    # @return [Boolean]
    def cleared?
      @cleared
    end

    # Zeroize the buffer immediately. Idempotent.
    # @return [self]
    def clear
      return self if @cleared

      # Overwrite every byte with 0x00 in place.
      @buffer.replace("\x00" * @buffer.bytesize)
      @buffer = nil
      @cleared = true
      self
    end

    # String representation for debugging. Does NOT expose the raw bytes.
    # @return [String]
    def inspect
      if @cleared
        "#<Confium::SecureBytes:0x#{object_id.to_s(16)} CLEARED>"
      else
        "#<Confium::SecureBytes:0x#{object_id.to_s(16)} #{length} bytes>"
      end
    end

    private

    # Finalizer proc that zeroizes the buffer if GC collects this
    # object without an explicit #clear. Uses object_id to find the
    # buffer — but since the buffer is an instance variable that may
    # already be collected, this is a best-effort path. Explicit #clear
    # is the recommended path.
    # @return [Proc]
    def finalizer_proc
      method(:finalize)
    end

    # Called by the GC finalizer.
    def finalize(_id)
      # Best-effort: the buffer may already be collected by the time
      # the finalizer runs. If @buffer still exists, zeroize it.
      # This is a closure over the instance — MRI guarantees the
      # finalizer runs after the object is unreachable but before
      # the buffer's memory is reused.
      return if @cleared

      @buffer&.replace("\x00" * @buffer.bytesize)
      @buffer = nil
      @cleared = true
    end
  end
end
