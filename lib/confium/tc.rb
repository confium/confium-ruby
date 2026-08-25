# frozen_string_literal: true

# Confium::TC provides Ruby access to the threshold cryptography
# interface exposed by the Confium Rust workspace.
#
# This module is loaded lazily via autoload from lib/confium.rb.
# It wraps the C FFI surface for threshold sessions, coordinator,
# re-sharing, and KEM operations.
#
# See: TODO.roadmap/04-threshold-cryptography.md in the main confium repo
# for the full interface specification.
module Confium
  module TC
    # The native extension defines Confium::TC; this namespace file
    # is eager-required from confium.rb, so autoloads never fire —
    # the pure-Ruby companions load with the namespace directly.
    require_relative 'tc/signing_session'
    require_relative 'tc/coordinator'
    require_relative 'tc/network_coordinator'
    require_relative 'tc/share_file'
  end
end
