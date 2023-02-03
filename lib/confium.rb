# frozen_string_literal: true

require_relative "confium/version"

module Confium

  def self.call_ffi_rc(fn, *args)
    rc = Confium::Lib.method(fn).call(*args)
    raise "FFI call to #{fn} failed (rc: #{rc})" unless rc.zero?
    rc
  end

  def self.call_ffi(fn, *args)
    call_ffi_rc(fn, *args)
    nil
  end

end

require_relative 'confium/lib'
require_relative 'confium/cfm'
require_relative 'confium/digest'
