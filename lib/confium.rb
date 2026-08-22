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
  major, minor = RUBY_VERSION.split('.').first(2).map(&:to_i)
  window = major > 3 || minor >= 3 ? '3.3' : "#{major}.#{minor}"
  begin
    require_relative "confium_native/#{window}/confium_native"
  rescue LoadError
    require_relative 'confium_native/confium_native'
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
  autoload :PKI,                  'confium/pki'
end

# Eager-load the Composite Signature JSON companion. The native
# extension defines Confium::Composite; this file reopens the class
# to add from_json transport.
require_relative 'confium/composite'

# Eager-load the Audit Ruby companion. The native extension registers
# `Confium::Audit` as a Ruby module with the `record`/`sink=`/`sink`
# methods; the companion file defines the Sink class hierarchy on top
# of that module.
require_relative 'confium/audit'

# Eager-load the TC ShareFile Ruby companion. The native extension
# defines `Confium::TC` as a Ruby module; this file adds the
# `ShareFile` class for filesystem-backed share persistence.
require_relative 'confium/tc/share_file'
