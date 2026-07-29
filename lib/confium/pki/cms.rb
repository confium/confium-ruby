# frozen_string_literal: true

# Confium::PKI::CMS namespace file.
#
# The CMS module itself is defined by the native Rust extension via
# magnus (SignedData, Content, VerificationResult). This file registers
# autoloads for pure-Ruby companions that wrap the native SignedData
# with a builder API.
module Confium
  module PKI
    module CMS
      autoload :SignedDataBuilder, "confium/pki/cms/signed_data_builder"
    end
  end
end
