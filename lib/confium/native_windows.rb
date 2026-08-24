# frozen_string_literal: true

module Confium
  # Pure resolution of which native-extension ABI windows to try, in
  # order. Extracted from the loader so the decision — the piece with
  # the release-incident history (3.1-window segfaults on 3.2, the
  # cross-major 3.3→4.0 TypeError, windowless platform gems) — is
  # testable without installing eight platform gems.
  module NativeWindows
    # Ordered candidate windows for +ruby_version+ (e.g. "3.4.8").
    #
    # Background: platform gems ship one extension per ABI window.
    # Ruby 3.2 broke the 3.1 ABI (object shapes) and rb-sys references
    # a VM pointer libruby stopped exporting in 3.3, so 3.1/3.2/4.0
    # get exact-minor builds while a 3.3-window binary loads on both
    # 3.3 and 3.4. The 3.3 fallback applies within the 3.x line
    # alone: a cross-major load (4.x) fails TypedData class-identity
    # checks, so 4.0 must not fall back to it.
    def self.candidates(ruby_version)
      minor = ruby_version[/\A\d+\.\d+/]
      raise ArgumentError, "not a ruby version: #{ruby_version.inspect}" unless minor

      major = ruby_version[/\A\d+/].to_i
      if major == 3 && Gem::Version.new(ruby_version) >= Gem::Version.new('3.3')
        [minor, '3.3'].uniq
      else
        [minor]
      end
    end
  end
end
