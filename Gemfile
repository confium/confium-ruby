# frozen_string_literal: true

source 'https://rubygems.org'

# Specify your gem's dependencies in confium.gemspec
gemspec

gem 'rake', '~> 13.0'

gem 'rubocop', '~> 1.21'

# Used by `scripts/sinatra_integration_test.sh` to verify the
# Sinatra verifier example actually serves HTTP.
gem 'puma', '~> 6.0', group: :development
gem 'rackup', group: :development
gem 'sinatra', '~> 4.0', group: :development

# CI tests Ruby 3.1+; parallel 2.x requires Ruby 3.3, so keep the
# 1.x line for matrix compatibility.
gem 'parallel', '~> 1.26'
