# frozen_string_literal: true

require "confium"

RSpec.describe Confium do
  it "exposes the native extension version" do
    expect(Confium::Native.version).to match(/\A\d+\.\d+\.\d+/)
  end

  it "reports loaded? as true once the extension is required" do
    expect(Confium::Native.loaded?).to be(true)
  end

  it "exposes the confium-core version the extension was built against" do
    expect(Confium.core_version).to match(/\A\d+\.\d+\.\d+/)
  end
end

RSpec.describe Confium::Transparency::MerkleTree do
  let(:artifact) { ("a" * 32).force_encoding("BINARY") }

  it "starts empty" do
    tree = described_class.new
    expect(tree.empty?).to be(true)
    expect(tree.length).to eq(0)
  end

  it "appends entries and reports the sequence number" do
    tree = described_class.new
    seq0 = tree.append(artifact)
    seq1 = tree.append(artifact)
    expect(seq0).to eq(0)
    expect(seq1).to eq(1)
    expect(tree.length).to eq(2)
    expect(tree.empty?).to be(false)
  end

  it "returns a 32-byte binary root" do
    tree = described_class.new
    tree.append(artifact)
    root = tree.root
    expect(root).to be_a(String)
    expect(root.encoding).to eq(Encoding::ASCII_8BIT)
    expect(root.bytesize).to eq(32)
  end

  it "verifies inclusion proofs for every leaf in a 3-entry tree" do
    tree = described_class.new
    3.times { tree.append(artifact) }
    root = tree.root
    [0, 1, 2].each do |seq|
      proof = tree.inclusion_proof(seq)
      expect(proof.sequence).to eq(seq)
      expect(proof.verify(root)).to be(true)
    end
  end

  it "rejects an inclusion proof against the wrong root" do
    tree = described_class.new
    tree.append(artifact)
    bad_root = ("\x00" * 32).force_encoding("BINARY")
    proof = tree.inclusion_proof(0)
    expect(proof.verify(bad_root)).to be(false)
  end

  it "exposes each step as a hash with sibling + side keys" do
    tree = described_class.new
    3.times { tree.append(artifact) }
    proof = tree.inclusion_proof(0)
    steps = proof.steps
    expect(steps.size).to eq(2)
    steps.each do |_index, step_hash|
      expect(step_hash).to be_a(Hash)
      expect(step_hash["sibling"].bytesize).to eq(32)
      expect(%w[left right]).to include(step_hash["side"])
    end
  end

  it "rejects artifact_hash inputs that aren't 32 bytes" do
    tree = described_class.new
    expect {
      tree.append(("a" * 16).force_encoding("BINARY"))
    }.to raise_error(ArgumentError, /artifact_hash must be exactly 32 bytes/)
  end
end
