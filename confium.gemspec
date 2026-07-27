# frozen_string_literal: true

require_relative "lib/confium/version"

Gem::Specification.new do |spec|
  spec.name = "confium"
  spec.version = Confium::VERSION
  spec.platform = Gem::Platform::RUBY

  spec.authors = ["Ribose Open"]
  spec.email = ["open.source@ribose.com"]

  spec.summary = "Ruby bindings for the Confium multi-stakeholder threshold cryptography framework."
  spec.description = "Confium provides threshold cryptography for Ruby: FROST / CMP20 / GG18 " \
                     "signing sessions, X.509 certificate issuance (CNML-ready), composite " \
                     "PQ-migration signatures, and transparency-log anchoring. Powered by a " \
                     "Rust native extension (magnus + rb_sys) — no separate C ABI to install."
  spec.homepage = "https://www.confium.org"
  spec.license = "BSD-2-Clause"

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/confium/confium-ruby/issues",
    "changelog_uri" => "https://github.com/confium/confium-ruby/blob/main/CHANGELOG.md",
    "homepage_uri" => spec.homepage,
    "source_code_uri" => "https://github.com/confium/confium-ruby",
    "rubygems_mfa_required" => "true",
  }

  # Rust extension — compiled at gem install via rb_sys.
  spec.extensions = ["ext/confium_native/extconf.rb"]

  spec.files = Dir.glob("{lib,ext}/**/*") + %w[
    CHANGELOG.md
    LICENSE.txt
    Rakefile
    README.adoc
    confium.gemspec
    Cargo.toml
    Cargo.lock
  ]
  spec.files.reject! { |f| File.directory?(f) }
  spec.files.reject! { |f| f =~ /\.(dll|so|dylib|lib|bundle)\Z/ }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 3.1.0"

  # Required for the Rust extension.
  spec.add_dependency "rb_sys", "~> 0.9.39"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2.0"
  spec.add_development_dependency "rake-compiler-dock", "~> 1.3"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
  spec.add_development_dependency "steep", "~> 1.5"
end
