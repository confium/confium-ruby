#!/usr/bin/env ruby
# frozen_string_literal: true
#
# AI/ML model signing use case — threshold-sign ML model weights for
# AI safety and supply-chain integrity. Ensures only authorized
# stakeholders can publish model updates, preventing unauthorized
# model swaps in production.
#
# Why threshold signing for AI models?
#
#   - **AI safety**: a rogue insider swapping model weights in
#     production is a top-3 AI safety risk. Threshold signing forces
#     a multi-stakeholder quorum before any model deployment.
#   - **Regulatory compliance**: the EU AI Act requires verifiable
#     provenance for high-risk AI systems. Threshold-signed model
#     weights provide cryptographic non-repudiation.
#   - **Supply-chain integrity**: models are distributed via model
#     registries (Hugging Face, MLflow, internal). Threshold-signed
#     manifests prove the model was reviewed by a quorum before
#     publication.
#
# Run: `bundle exec ruby examples/ai_model_signing.rb`

require "base64"
require "digest"
require "json"
require "openssl"
require "confium"

puts "== AI/ML Model Signing — Threshold Ceremony =="
puts
puts "Scenario: a team of ML engineers, security reviewers, and a"
puts "compliance officer must jointly approve a production model update."

puts
puts "== Setup: AI governance quorum (3-of-5) =="
kg = Confium::TC::Cmp20.keygen(3, 5)
puts "  model signing joint public key: 0x#{kg["public_key"].unpack1("H*")[0, 24]}..."
puts "  shares: ml_engineer, security_reviewer, compliance_officer,"
puts "          ai_safety_lead, release_manager"

puts
puts "== Model manifest (simulated) =="
# In production: hash the actual safetensors / pickle / ONNX file.
model_weights = "simulated-transformer-weights-layer-0-to-99..."
model_hash = Digest::SHA256.hexdigest(model_weights)
manifest = {
  model_name: "gpt-confium-7b",
  version: "2.1.0",
  architecture: "transformer-decoder",
  parameters: 7_000_000_000,
  training_data_cutoff: "2026-06-30",
  safety_eval: {
    toxic_prompt_pass_rate: 0.997,
    jailbreak_resistance: "AAA",
    bias_audit: "passed",
  },
  weights_hash: model_hash,
  weights_size_bytes: 14_000_000_000,
  license: "Apache-2.0",
}
manifest_json = JSON.generate(manifest)
puts "  model: #{manifest[:model_name]} v#{manifest[:version]}"
puts "  parameters: #{manifest[:parameters] / 1_000_000_000}B"
puts "  weights SHA-256: #{model_hash[0, 24]}..."
puts "  safety eval: #{manifest[:safety_eval][:bias_audit]}"

puts
puts "== 3-of-5 quorum signs the model manifest =="
three_shares = kg["shares"].first(3)
puts "  participating: ml_engineer, security_reviewer, ai_safety_lead"
sig = Confium::TC::Cmp20.sign(three_shares, 3, manifest_json)
puts "  model signature: 0x#{sig.unpack1("H*")[0, 24]}... (#{sig.bytesize} bytes)"

puts
puts "== Publish signed model to registry =="
signed_manifest = {
  manifest: Base64.strict_encode64(manifest_json),
  signature: {
    algorithm: "ECDSA-P256",
    threshold_scheme: "CMP20-ECDSA-P256",
    quorum: "3-of-5",
    value: Base64.strict_encode64(sig),
    public_key: Base64.strict_encode64(kg["public_key"]),
    signers: %w[ml_engineer security_reviewer ai_safety_lead],
  },
}
puts "  registry: huggingface.co/confium/gpt-confium-7b"
puts "  signed manifest: #{JSON.generate(signed_manifest).bytesize} bytes"

puts
puts "== Production inference server verifies model before loading =="
loaded_manifest = JSON.parse(JSON.generate(signed_manifest))
loaded_json = Base64.strict_decode64(loaded_manifest["manifest"])
loaded_sig = Base64.strict_decode64(loaded_manifest["signature"]["value"])
loaded_pk = Base64.strict_decode64(loaded_manifest["signature"]["public_key"])

asn1 = OpenSSL::ASN1::Sequence([
  OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
    OpenSSL::ASN1::ObjectId("prime256v1"),
  ]),
  OpenSSL::ASN1::BitString(loaded_pk),
])
pkey = OpenSSL::PKey::EC.new(asn1.to_der)
r = OpenSSL::BN.new(loaded_sig[0, 32], 2)
s = OpenSSL::BN.new(loaded_sig[32, 32], 2)
der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
digest = Digest::SHA256.digest(loaded_json)

if pkey.dsa_verify_asn1(digest, der)
  parsed = JSON.parse(loaded_json)
  puts "  ✓ model manifest verified — 3-of-5 governance quorum confirmed"
  puts "  ✓ model: #{parsed["model_name"]} v#{parsed["version"]}"
  puts "  ✓ safety eval: #{parsed["safety_eval"]["bias_audit"]}"
  puts "  ✓ loading model into inference server..."
else
  abort "  ✗ model manifest FAILED — refusing to load unverified model"
end

puts
puts "== Anchor to transparency log (AI provenance) =="
tree = Confium::Transparency::MerkleTree.new
tree.append(Digest::SHA256.digest(loaded_json + loaded_sig))
puts "  transparency root: 0x#{tree.root.unpack1("H*")[0, 24]}..."
puts
puts "Done. The AI model is signed by a 3-of-5 governance quorum,"
puts "verified by the inference server before loading, and anchored"
puts "to a transparency log for AI provenance and non-repudiation."
puts
puts "This prevents: unauthorized model swaps, supply-chain attacks"
puts "on model registries, and silent rollback to unsafe versions."
