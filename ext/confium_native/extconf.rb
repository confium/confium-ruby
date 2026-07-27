# frozen_string_literal: true

require "mkmf"
require "rb_sys/mkmf"

create_rust_makefile("confium_native") do |r|
  r.profile = ENV.fetch("RB_SYS_CARGO_PROFILE", :dev).to_sym
  r.use_stable_api_compiled_fallback = true
  r.force_install_rust_toolchain = false
end
