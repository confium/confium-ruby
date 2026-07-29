# frozen_string_literal: true

# Confium::PKI namespace file.
#
# The PKI module itself is defined by the native Rust extension via
# magnus at require time (see ext/confium_native/src/pki.rs). This file
# registers pure-Ruby autoloads for the PKI submodules that wrap or
# extend the native surface.
module Confium
  module PKI
    autoload :CMS, "confium/pki/cms"
  end
end
