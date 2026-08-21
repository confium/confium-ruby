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
    autoload :Session, 'confium/tc/session'
    autoload :Coordinator, 'confium/tc/coordinator'
  end
end
