# frozen_string_literal: true

# Pre-compiled native gems, built on native-arch runners.
#
# rake-compiler-dock cross-compilation is blocked for this gem: the
# dock images (rake-compiler-dock 1.12, still Ubuntu 20.04) ship gcc
# 9.4 and LLVM-10-era cross toolchains, while the vendored RNP stack
# builds Botan 3.12, which requires gcc 11+ / clang 12+. Instead each
# platform builds on a runner whose architecture IS the target
# (ubuntu-latest, ubuntu-24.04-arm, macos-13, macos-15), where the
# vendored C/C++ build compiles natively.
#
# The extension is compiled against the oldest supported Ruby (3.1)
# and loaded by newer Rubies through the stable C extension ABI; the
# workflow installs the packaged gem on Ruby 3.1 and 3.4 to guard
# that assumption.
#
# Usage:
#   bundle exec rake compile
#   bundle exec rake native_gem:package[arm64-darwin]

NATIVE_GEM_PLATFORMS = %w[
  x86_64-linux
  aarch64-linux
  x86_64-darwin
  arm64-darwin
].freeze

namespace :native_gem do
  desc 'Build the source gem (no native binary)'
  task :source do
    sh 'gem build confium.gemspec'
  end

  desc 'Package the compiled extension as a pre-built platform gem'
  task :package, [:platform] do |_t, args|
    platform = args[:platform] || raise(ArgumentError, 'platform required')
    expected = Gem::Platform.new(platform)
    runner = Gem::Platform.new(RbConfig::CONFIG['arch'])
    # Gem::Platform#=== performs platform matching (nil fields are wildcards).
    matches = expected === runner # rubocop:disable Style/CaseEquality
    raise "refusing to stamp #{expected}: this machine is #{runner}" unless matches

    binary = Dir['lib/confium_native/confium_native.{so,bundle,dll}'].first
    raise 'extension not compiled; run `rake compile` first' unless binary

    spec = Gem::Specification.load('confium.gemspec')
    spec.platform = expected
    # Pre-built gem: ship the compiled extension instead of the Rust
    # sources (the vendored RNP tree would bloat every platform gem)
    # and run no extconf at install time.
    spec.files = spec.files.grep_v(%r{\Aext/}) + [binary]
    spec.extensions = []

    require 'rubygems/package'
    FileUtils.mkdir_p('pkg')
    path = File.join('pkg', "#{spec.full_name}.gem")
    Gem::Package.build(spec, nil, nil, path)
    puts "packaged #{path} (#{File.size(path)} bytes)"
  end
end
