# frozen_string_literal: true

require 'rake/clean'
require 'bundler/gem_tasks'

require 'rb_sys/extensiontask'
gemspec = Gem::Specification.load('confium.gemspec')
RbSys::ExtensionTask.new('confium_native', gemspec) do |ext|
  ext.lib_dir = 'lib/confium_native'
end

# Tooling tasks are dev-only and are not needed to build the
# extension. Guard the requires so minimal environments (e.g. release
# tooling containers) can still load this Rakefile.
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
