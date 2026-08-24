# frozen_string_literal: true

require 'mkmf'
require 'rb_sys/mkmf'

create_rust_makefile('confium_native') do |r|
  r.profile = ENV.fetch('RB_SYS_CARGO_PROFILE', :dev).to_sym
  r.use_stable_api_compiled_fallback = true
  r.force_install_rust_toolchain = false
  # rb_sys only threads --features through to cargo when the builder
  # has a non-empty feature list; seeding it from the env var makes
  # RB_SYS_CARGO_FEATURES=pgp bundle exec rake compile work.
  r.features = ENV.fetch('RB_SYS_CARGO_FEATURES', '')
                  .split(',').map(&:strip).reject(&:empty?)
end
