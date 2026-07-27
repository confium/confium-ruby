# frozen_string_literal: true

# Cross-platform native gem build via rake-compiler-dock.
#
# Builds pre-compiled native gems for Linux (x86_64, aarch64), macOS
# (x86_64, arm64), and Windows (x86_64-mingw32). Consumers can then
# `gem install confium-0.1.0-x86_64-linux` without needing a Rust
# toolchain locally.
#
# Usage:
#   bundle exec rake native_gem:all       # build all platforms
#   bundle exec rake native_gem:x86_64-linux
#
# This is a v0.2.0 release-engineering step. v0.1.0 ships as a source
# gem that requires Rust at install time.

require "rake_compiler_dock"

namespace :native_gem do
  PLATFORMS = %w[
    x86_64-linux
    aarch64-linux
    x86_64-darwin
    arm64-darwin
    x64-mingw-ucrt
    x64-mingw32
  ].freeze

  desc "Build the source gem (no native binary)"
  task :source do
    sh "gem build confium.gemspec"
  end

  desc "Build native gems for all platforms via rake-compiler-dock"
  task :all do
    PLATFORMS.each do |platform|
      Rake::Task["native_gem:#{platform}"].invoke
    end
  end

  PLATFORMS.each do |platform|
    desc "Build the native gem for #{platform}"
    task platform do
      RakeCompilerDock.sh <<-SH, platform: platform
        bundle install
        bundle exec rake native:confium_native#{platform == "x64-mingw-ucrt" ? "" : ":" + platform}
        gem build confium.gemspec --output confium-#{platform}.gem
      SH
    end
  end
end
