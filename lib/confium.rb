# frozen_string_literal: true

# Confium is the Ruby entry point for the Confium cryptographic framework.
#
# This file opens the {Confium} module and registers an autoload entry for
# each top-level child constant. Per the project's global rules there is no
# `require_relative` anywhere in `lib/`: every child is loaded lazily on
# first reference via Ruby's `autoload` mechanism, so each namespace owns
# the load paths of its own children.
#
# New top-level constants (Cipher, AEAD, KDF, RNG, Signature, KEM, Keyfmt,
# Keystore, Sensitive, ...) should be added here as one `autoload` line as
# the backing files land. This keeps the file open for extension (OCP)
# without touching existing entries.
module Confium
  autoload :VERSION,  "confium/version"
  autoload :FFI,      "confium/ffi"
  autoload :Crypto,   "confium/crypto"
  autoload :Lib,      "confium/lib"
  autoload :CFM,      "confium/cfm"
  autoload :Digest,   "confium/digest"

  # Invoke an FFI function that returns a uint32 status code, raising when
  # the call did not succeed (non-zero return).
  def self.call_ffi_rc(fn, *args)
    rc = Confium::Lib.method(fn).call(*args)
    raise "FFI call to #{fn} failed (rc: #{rc})" unless rc.zero?

    rc
  end

  # Invoke an FFI function that returns a uint32 status code, discarding
  # the return value. Raises on non-zero status.
  def self.call_ffi(fn, *args)
    call_ffi_rc(fn, *args)
    nil
  end
end
