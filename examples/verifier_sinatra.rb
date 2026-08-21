#!/usr/bin/env ruby
# frozen_string_literal: true

#
# Sinatra verifier quickstart — exposes three endpoints that exercise
# the most common verifier workflows:
#
#   POST /verify/composite     — verify a composite multi-alg signature
#   POST /verify/inclusion     — verify a transparency-log inclusion proof
#   GET  /health               — version + binding status
#
# Run with:
#   bundle add sinatra --version "~> 4.0"
#   ruby examples/verifier_sinatra.rb
#   # in another shell:
#   curl http://localhost:4567/health
#
# Production notes: this example uses Sinatra's default WEBrick. For
# real deployments, swap in Puma (bundle add puma) and add TLS at the
# reverse proxy layer.

require 'json'
require 'sinatra/base'
require 'confium'

class VerifierApp < Sinatra::Base
  # 5 MiB request cap — well above any realistic sig payload, well
  # below the host's typical memory pressure point.
  set :max_request_size, 5 * 1024 * 1024

  before do
    content_type :json
    halt 413, JSON.generate(error: 'request too large') if request.content_length.to_i > settings.max_request_size
  end

  # Health check — confirms the native extension is loaded.
  get '/health' do
    JSON.generate(
      ok: true,
      version: Confium::VERSION,
      core_version: Confium.core_version
    )
  end

  # Composite signature verification. Expects JSON:
  #   {
  #     "composite": "<composite sig JSON>",
  #     "message":   "<hex bytes of signed message>"
  #   }
  #
  # The composite sig JSON shape matches Confium::Composite::Signature#from_json.
  post '/verify/composite' do
    body = JSON.parse(request.body.read)
    sig_json = body.fetch('composite')
    message = [body.fetch('message')].pack('H*')

    sig = Confium::Composite::Signature.from_json(sig_json)
    result = sig.verify(message, {})

    JSON.generate(
      all_verified: result.all_verified?,
      per_component: result.per_component
    )
  rescue KeyError => e
    halt 400, JSON.generate(error: "missing field: #{e.message}")
  rescue StandardError => e
    halt 400, JSON.generate(error: e.message)
  end

  # Transparency-log inclusion proof verification. Expects JSON:
  #   {
  #     "leaf_hash":    "<hex 32 bytes>",
  #     "proof_steps":  [{"sibling": "<hex 32 bytes>", "side": "left|right"}, ...],
  #     "root":         "<hex 32 bytes>",
  #     "sequence":     <integer>
  #   }
  post '/verify/inclusion' do
    body = JSON.parse(request.body.read)
    leaf_hash = [body.fetch('leaf_hash')].pack('H*')
    root      = [body.fetch('root')].pack('H*')

    proof = Confium::Transparency::InclusionProof.new(
      sequence: body.fetch('sequence'),
      steps: body.fetch('proof_steps').map do |s|
        {
          'sibling' => [s.fetch('sibling')].pack('H*'),
          'side' => s.fetch('side')
        }
      end
    )

    ok = Confium::Transparency::MerkleTree.verify_inclusion(
      entry: leaf_hash,
      proof: proof,
      root: root
    )
    JSON.generate(verified: ok)
  rescue KeyError => e
    halt 400, JSON.generate(error: "missing field: #{e.message}")
  rescue StandardError => e
    halt 400, JSON.generate(error: e.message)
  end

  # Custom 404 — JSON, not HTML.
  not_found do
    content_type :json
    JSON.generate(error: 'not found')
  end
end

VerifierApp.run! if __FILE__ == $PROGRAM_NAME
