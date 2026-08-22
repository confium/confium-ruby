# frozen_string_literal: true

# Confium::Transparency namespace file.
#
# The Transparency module itself is defined by the native Rust
# extension via magnus at require time. This file registers
# pure-Ruby autoloads for the Transparency submodules.
module Confium
  module Transparency
    autoload :OTS, 'confium/transparency/ots'
  end
end
