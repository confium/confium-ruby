# frozen_string_literal: true

require "ffi"

# {Confium::FFI} is the namespace for everything that touches the native
# Confium shared library through Ruby-FFI.
#
# This file registers autoload entries for the planned FFI helper modules
# (Library, Error, Options). They are listed in the TODO #14 architecture
# (see `TODO.finalize/14-ruby-bindings-architecture.md`) and will be added
# as the bindings grow; until then the autoloads are inert — they only
# trigger a load when the corresponding constant is first referenced.
#
# Note: the legacy FFI library wrapper still lives at `Confium::Lib`
# (file `confium/lib.rb`) and is autoloaded from `confium.rb`. It will be
# migrated into `Confium::FFI::Library` in a follow-up.
module Confium
  module FFI
    autoload :Library, "confium/ffi/library"
    autoload :Error,   "confium/ffi/error"
    autoload :Options, "confium/ffi/options"
  end
end
