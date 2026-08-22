# frozen_string_literal: true

# Steepfile for RBS type checking of the confium Ruby gem.
#
# Run `bundle exec steep check` to type-check the gem's pure-Ruby
# code against the signatures in sig/. The native extension classes
# are defined in Rust via magnus; their signatures live in
# sig/confium.rbs and are enforced through how lib/ uses them.
#
# Spec files are not checked: RSpec's DSL has no RBS signatures, so
# type-checking specs is noise.

target :lib do
  signature 'sig'
  library 'json'
  library 'fileutils'

  check 'lib'

  # FFI-layer files: the ffi gem has no RBS signatures, so these can
  # never type-check. They are exercised by the spec suite instead.
  ignore 'lib/confium/lib.rb'
  ignore 'lib/confium/ffi.rb'
  ignore 'lib/confium/digest.rb'
  ignore 'lib/confium/cfm.rb'

  # TC session machinery — typed as a follow-up.
  ignore 'lib/confium/tc/session.rb'
  ignore 'lib/confium/tc/coordinator.rb'
  ignore 'lib/confium/tc/session_stub.rb'
end
