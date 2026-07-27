# frozen_string_literal: true

# Confium is the Ruby entry point for the Confium cryptographic framework.
#
# The native Rust extension is loaded first; everything else (Cert, CMS,
# Composite, Transparency, TC::*, etc.) is registered by the extension
# via magnus when this file is required.
#
# Pure-Ruby companions (the error hierarchy, Enumerable mixins, etc.)
# are loaded lazily via autoload — see lib/confium/<name>.rb.

require_relative "confium/version"

begin
  require_relative "confium_native/confium_native"
rescue LoadError => e
  warn "confium: native extension not built — run `bundle exec rake compile`"
  raise e
end

module Confium
  # Error hierarchy autoloads. Each subclass lives in its own file so
  # callers can `autoload :FooError, "confium/errors/foo"` and avoid
  # loading the whole hierarchy if they only rescue one type.
  autoload :Error,                "confium/errors"
  autoload :ParseError,           "confium/errors/parse_error"
  autoload :ValidationError,      "confium/errors/validation_error"
  autoload :VerificationError,    "confium/errors/verification_error"
  autoload :ThresholdError,       "confium/errors/threshold_error"
  autoload :CryptoError,          "confium/errors/crypto_error"
  autoload :NotFoundError,        "confium/errors/not_found_error"
  autoload :IndexError,           "confium/errors/index_error"
  autoload :UnresolvedSignerError,"confium/errors/unresolved_signer_error"
  autoload :PolicyViolationError, "confium/errors/policy_violation_error"
end
