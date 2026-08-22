# frozen_string_literal: true

# Pre-compiled native gems, built on native-arch runners.
#
# rake-compiler-dock cross-compilation is blocked for this gem: the
# dock images (rake-compiler-dock 1.12, still Ubuntu 20.04) ship gcc
# 9.4 and LLVM-10-era cross toolchains, while the vendored RNP stack
# builds Botan 3.12, which requires gcc 11+ / clang 12+. Instead each
# platform builds on a runner whose architecture IS the target
# (ubuntu-latest, ubuntu-24.04-arm, macos-15-intel, macos-15), where
# the vendored C/C++ build compiles natively.
#
# One .so cannot span every supported Ruby: rb-sys references
# ruby_current_vm_ptr when compiled against Ruby <= 3.2, and libruby
# stopped exporting it in 3.3. Platform gems therefore carry one
# extension per C-ABI window — 3.1 (loads on 3.1/3.2) and 3.3 (loads
# on 3.3+) — and lib/confium.rb picks the directory for the running
# Ruby. The workflow's install-check job loads every supported Ruby
# (3.1–3.4) before anything can publish.
#
# Usage (CI stages lib/confium_native/<window>/ first; locally the
# task also falls back to the flat `rake compile` output):
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
    windows = Dir['lib/confium_native/{3.1,3.3}/confium_native.{so,bundle}']
    flat = Dir['lib/confium_native/confium_native.{so,bundle}'].first
    if windows.empty?
      # Local flow: packaging the machine's own compile output, so the
      # runner arch must match the requested platform. CI instead stages
      # per-window binaries built by the platform-matched build matrix.
      expected = Gem::Platform.new(platform)
      runner = Gem::Platform.new(RbConfig::CONFIG['arch'])
      # Gem::Platform#=== performs platform matching (nil fields are wildcards).
      matches = expected === runner # rubocop:disable Style/CaseEquality
      raise "refusing to stamp #{expected}: this machine is #{runner}" unless matches

      raise 'extension not compiled; run `rake compile` first' unless flat

      binaries = [flat]
    else
      binaries = windows
    end

    spec = Gem::Specification.load('confium.gemspec')
    spec.platform = Gem::Platform.new(platform)
    # Pre-built gem: ship the compiled extension instead of the Rust
    # sources (the vendored RNP tree would bloat every platform
    # gem) and run no extconf at install time. rb_sys exists for
    # extconf-based source builds only, so it is not a dependency
    # here — with it recorded, installing the platform gem offline
    # or with --local fails to resolve it.
    spec.files = spec.files.grep_v(%r{\Aext/}) + binaries
    spec.extensions = []
    spec.dependencies.reject! { |d| d.name == 'rb_sys' }

    require 'rubygems/package'
    FileUtils.mkdir_p('pkg')
    path = File.join('pkg', "#{spec.full_name}.gem")
    Gem::Package.build(spec, nil, nil, path)
    puts "packaged #{path} (#{File.size(path)} bytes): #{binaries.join(', ')}"
  end
end
