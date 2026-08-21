# frozen_string_literal: true

# Cross-platform native gem builds via rb-sys-dock.
#
# rb-sys-dock runs the rbsys/<platform> Docker images (rake-compiler-
# dock mri images layered with a Rust toolchain and cross C/C++
# compilers) and executes `rake native:<platform> gem` inside them,
# producing pkg/confium-<version>-<platform>.gem. CI drives the same
# build through oxidize-rb/actions/cross-gem; these tasks exist for
# local use and require Docker.
#
# Usage:
#   bundle exec rake native_gem:x86_64-linux
#   bundle exec rake native_gem:all
#
# Windows targets are not built: the vendored RNP (json-c + botan)
# C/C++ build has no MSVC/mingw cross story.

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

  desc 'Build native gems for all platforms via rb-sys-dock'
  task :all do
    NATIVE_GEM_PLATFORMS.each do |platform|
      Rake::Task["native_gem:#{platform}"].invoke
    end
  end

  NATIVE_GEM_PLATFORMS.each do |platform|
    desc "Build the native gem for #{platform} via rb-sys-dock"
    task platform do
      sh 'bundle', 'exec', 'rb-sys-dock', '--platform', platform, '--build'
    end
  end
end
