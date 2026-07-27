# frozen_string_literal: true

# Steepfile for RBS type checking of the confium Ruby gem.
#
# Run `bundle exec steep check` to type-check the gem's Ruby code
# against the signatures in sig/. The native extension classes are
# defined in Rust via magnus; this Steepfile only checks the pure-Ruby
# portion (`lib/confium.rb`) — the Rust-exposed classes are typed
# via sig/confium.rbs and surface in consumer code that uses them.

target :lib do
  signature "sig"

  check "lib/confium.rb"
  check "lib/confium/version.rb"
end

target :specs do
  signature "sig"
  check "spec/confium/transparency_spec.rb"
  check "spec/confium/composite_spec.rb"
  check "spec/confium/attributes_spec.rb"
  check "spec/confium/pki_spec.rb"
  check "spec/confium/deployment_spec.rb"
  check "spec/confium/tc_spec.rb"
  check "spec/integration_cnml_workflow_spec.rb"
end

# Configure library paths so steep can find the gem's own requires.
configure_code_diagnostics(Diagnostic.new)
