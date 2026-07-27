# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"
RSpec::Core::RakeTask.new(:spec)

require "rubocop/rake_task"
RuboCop::RakeTask.new

require "rb_sys/extensiontask"
gemspec = Gem::Specification.load("confium.gemspec")
RbSys::ExtensionTask.new("confium_native", gemspec) do |ext|
  ext.lib_dir = "lib/confium_native"
end

task compile: :clean
task default: %i[compile spec rubocop]
