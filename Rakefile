# frozen_string_literal: true

require 'rake/clean'
require 'bundler/gem_tasks'

require 'rb_sys/extensiontask'
gemspec = Gem::Specification.load('confium.gemspec')
RbSys::ExtensionTask.new('confium_native', gemspec) do |ext|
  ext.lib_dir = 'lib/confium_native'
  # Cross-compiled native gems: the rb-sys-dock images set RUBY_TARGET,
  # which rb_sys reads to define the native:<platform> and gem tasks
  # that stamp the built gem with the target platform. Windows is
  # absent: the vendored RNP build has no MSVC/mingw cross story
  # (see rakelib/native_gem.rake).
  ext.cross_compile = true
  ext.cross_platform = %w[
    aarch64-linux
    x86_64-linux
    x86_64-darwin
    arm64-darwin
  ]
end

# Tooling tasks are dev-only. The cross-compile containers ship rake,
# rake-compiler and rb_sys but not the full dev bundle, so these
# requires must not break loading the Rakefile there.
begin
  require 'rspec/core/rake_task'
  RSpec::Core::RakeTask.new(:spec)
rescue LoadError
  nil
end

begin
  require 'rubocop/rake_task'
  RuboCop::RakeTask.new
rescue LoadError
  nil
end

task compile: :clean
task default: %i[compile spec rubocop]
