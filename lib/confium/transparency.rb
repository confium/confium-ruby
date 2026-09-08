# frozen_string_literal: true

# Confium::Transparency namespace file.
#
# The Transparency module itself is defined by the native Rust
# extension via magnus at require time. This file registers
# pure-Ruby autoloads for the Transparency submodules.
# `require`, not `autoload`: the native extension defines the OTS
# constant at load time, which would shadow the autoload entry and
# keep this file from ever running — the Ruby-level convenience
# methods would silently vanish.
require 'confium/transparency/ots'
