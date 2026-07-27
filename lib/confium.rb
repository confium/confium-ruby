# frozen_string_literal: true

require_relative "confium/version"

# Confium is the Ruby entry point for the Confium cryptographic framework.
#
# Native Rust extension is loaded first; everything else (Cert, CMS,
# Composite, Transparency, TC::*, etc.) is registered by the extension
# via magnus when this file is required.
begin
  require_relative "confium_native/confium_native"
rescue LoadError => e
  warn "confium: native extension not built — run `bundle exec rake compile`"
  raise e
end

module Confium
  class Error < StandardError; end
end
