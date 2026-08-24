# frozen_string_literal: true

# Confium is the Ruby entry point for the Confium cryptographic framework.
#
# The native Rust extension is loaded first; everything else (Cert, CMS,
# Composite, Transparency, TC::*, etc.) is registered by the extension
# via magnus when this file is required.
#
# Pure-Ruby companions (the error hierarchy, Enumerable mixins, etc.)
# are loaded lazily via autoload — see lib/confium/<name>.rb.

require_relative 'confium/version'

begin
  # Pre-built platform gems ship one extension per C-ABI window
  # (Ruby 3.2 broke the 3.1 ABI — object shapes — and rb-sys
  # references the VM pointer libruby stopped exporting in 3.3, so
  # 3.1 and 3.2 get exact-minor builds while 3.3 covers 3.3+).
  # Source builds install the extension flat, without a version
  # directory.
  minor = RUBY_VERSION[/\A\d+\.\d+/]
  dlext = RbConfig::CONFIG['DLEXT'] || 'so'
  major = RUBY_VERSION[/\A\d+/].to_i
  # 3.3-window binaries load on 3.3/3.4 only; a cross-major load
  # (4.x) fails TypedData class checks, so the fallback applies
  # within the 3.x line alone.
  candidates = major == 3 && Gem::Version.new(RUBY_VERSION) >= Gem::Version.new('3.3') ? [minor, '3.3'].uniq : [minor]
  # Windows gems carry an exact-minor window per Ruby (a PE import
  # names the version-specific ruby DLL); other platforms share the
  # 3.3 window for 3.3+. Prefer the exact minor when present.
  windowed = candidates.filter_map do |w|
    path = File.expand_path("confium_native/#{w}/confium_native.#{dlext}", __dir__ || '.')
    w if File.exist?(path)
  end
  if windowed.empty?
    require_relative 'confium_native/confium_native'
  else
    windowed.each do |w|
      require_relative "confium_native/#{w}/confium_native"
      break
    rescue LoadError => e
      # A present-but-unloadable binary raises its real dlopen
      # error once every window has been tried.
      raise e if w == windowed.last
    end
  end
rescue LoadError => e
  warn 'confium: native extension not built — run `bundle exec rake compile`'
  raise e
end

# Register autoloads on the native-defined PKI::CMS module so Ruby
# companions like SignedDataBuilder load on first reference. Eager-
# required because the module already exists at this point.
require_relative 'confium/pki/cms'

# The native extension defines Confium::OpenPGP with _native_armor /
# _native_dearmor. This file adds the idiomatic Ruby wrappers with
# default args. Eager-required for the same reason as PKI::CMS.
require_relative 'confium/openpgp'

module Confium
  # Error hierarchy autoloads. Each subclass lives in its own file so
  # callers can `autoload :FooError, "confium/errors/foo"` and avoid
  # loading the whole hierarchy if they only rescue one type.
  autoload :Error,                'confium/errors'
  autoload :ParseError,           'confium/errors/parse_error'
  autoload :ValidationError,      'confium/errors/validation_error'
  autoload :VerificationError,    'confium/errors/verification_error'
  autoload :ThresholdError,       'confium/errors/threshold_error'
  autoload :CryptoError,          'confium/errors/crypto_error'
  autoload :NotFoundError,        'confium/errors/not_found_error'
  autoload :IndexError,           'confium/errors/index_error'
  autoload :UnresolvedSignerError, 'confium/errors/unresolved_signer_error'
  autoload :PolicyViolationError, 'confium/errors/policy_violation_error'
  autoload :SecureBytes,          'confium/secure_bytes'
  autoload :Policy,               'confium/policy'
  # PKI is native-defined, so an autoload would never fire; the
  # namespace file is eager-required and registers the pure-Ruby
  # submodules (CMS, CertificateBuilder, CNML) as autoloads.
  require_relative 'confium/pki'
end

# Eager-load the Composite Signature JSON companion. The native
# extension defines Confium::Composite; this file reopens the class
# to add from_json transport.
require_relative 'confium/composite'

# Eager-load the Transparency namespace for the OTS autoload (the
# module itself is native-defined).
require_relative 'confium/transparency'

# Eager-load the Audit Ruby companion. The native extension registers
# `Confium::Audit` as a Ruby module with the `record`/`sink=`/`sink`
# methods; the companion file defines the Sink class hierarchy on top
# of that module.
require_relative 'confium/audit'

# Eager-load the TC namespace file: `Confium::TC` is native-defined,
# so an autoload here would never fire (the PKI pattern). It
# registers the pure-Ruby Session/Coordinator companions and the
# ShareFile class for filesystem-backed share persistence.
require_relative 'confium/tc'
