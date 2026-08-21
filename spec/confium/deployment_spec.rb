# frozen_string_literal: true

require 'confium'

RSpec.describe Confium::Identity do
  describe '.actor_types' do
    it 'returns the six canonical actor types' do
      types = described_class.actor_types
      expect(types).to eq(%w[
                            manufacturer
                            testing_lab
                            issuing_authority_officer
                            biml_director
                            quorum_coordinator
                            verifier
                          ])
    end
  end
end

RSpec.describe Confium::Identity::Actor do
  let(:actor_json) do
    '{
      "actor_id": "biml-director-alice",
      "actor_type": "biml_director",
      "quorum_id": "biml-quorum",
      "signing_key": {"kind":"software","key_id":"alice-signing","algorithm":"Ed25519"},
      "certificate_chain_der": [],
      "attributes": {"expertise":[],"role":[],"custom":{}},
      "registered_at": "2026-07-27T00:00:00Z"
    }'
  end

  describe '.from_json' do
    it 'parses a complete actor identity' do
      actor = described_class.from_json(actor_json)
      expect(actor).to be_a(described_class)
      expect(actor.actor_id).to eq('biml-director-alice')
      expect(actor.actor_type).to eq('biml_director')
      expect(actor.quorum_id).to eq('biml-quorum')
    end

    it 'raises on malformed JSON' do
      expect { described_class.from_json('{not json') }.to raise_error(RuntimeError)
    end
  end

  describe '#to_json' do
    it 'round-trips through from_json' do
      actor = described_class.from_json(actor_json)
      round = described_class.from_json(actor.to_json)
      expect(round.actor_id).to eq(actor.actor_id)
      expect(round.actor_type).to eq(actor.actor_type)
    end
  end

  describe '#registered_at' do
    it 'returns an ISO8601 timestamp' do
      actor = described_class.from_json(actor_json)
      expect(actor.registered_at).to match(/\A\d{4}-\d{2}-\d{2}T/)
    end
  end

  describe '#expires_at' do
    it 'returns nil when no expiry is set' do
      actor = described_class.from_json(actor_json)
      expect(actor.expires_at).to be_nil
    end

    it 'returns an ISO8601 timestamp when expiry is set' do
      json = actor_json.sub(
        '"registered_at": "2026-07-27T00:00:00Z"',
        '"registered_at": "2026-07-27T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z"'
      )
      actor = described_class.from_json(json)
      expect(actor.expires_at).to match(/\A2030-/)
    end
  end

  describe '#certificate_count' do
    it 'returns the chain length' do
      actor = described_class.from_json(actor_json)
      expect(actor.certificate_count).to eq(0)
    end
  end
end

RSpec.describe Confium::Config::Manifest do
  let(:manifest_toml) do
    <<~TOML
      [deployment]
      name = "Test Deployment"
      operator = "Ribose"
      manifest_version = 1

      [[tiers]]
      name = "Manufacturer"
      role = "manufacturer"
      signing_algorithm = "Ed25519"
      threshold = { t = 3, n = 5 }

      [[tiers]]
      name = "BIML"
      role = "biml_director"
      signing_algorithm = "Ed25519"
      threshold = { t = 5, n = 9 }

      [[quorums]]
      name = "Manufacturers"
      coordinator = "coord-001"
      threshold = { t = 3, n = 5 }
    TOML
  end

  describe '.from_toml' do
    it 'parses a complete manifest' do
      m = described_class.from_toml(manifest_toml)
      expect(m).to be_a(described_class)
      expect(m.deployment_name).to eq('Test Deployment')
      expect(m.operator).to eq('Ribose')
      expect(m.manifest_version).to eq(1)
    end

    it 'raises on malformed TOML' do
      expect { described_class.from_toml('not = = toml') }.to raise_error(RuntimeError)
    end
  end

  describe '#tier_count / #tier_name_at' do
    it 'iterates the tiers in declaration order' do
      m = described_class.from_toml(manifest_toml)
      expect(m.tier_count).to eq(2)
      expect(m.tier_name_at(0)).to eq('Manufacturer')
      expect(m.tier_name_at(1)).to eq('BIML')
    end

    it 'raises IndexError for out-of-range tier index' do
      m = described_class.from_toml(manifest_toml)
      expect { m.tier_name_at(99) }.to raise_error(IndexError, /out of range/)
    end
  end

  describe '#quorum_count' do
    it 'returns the number of quorum definitions' do
      m = described_class.from_toml(manifest_toml)
      expect(m.quorum_count).to eq(1)
    end
  end

  describe '#valid? / #validate' do
    it 'returns true and empty errors for a well-formed manifest' do
      m = described_class.from_toml(manifest_toml)
      expect(m.valid?).to be(true)
      expect(m.validate).to eq([])
    end

    it 'flags an unsupported manifest version' do
      bad = manifest_toml.sub('manifest_version = 1', 'manifest_version = 99')
      m = described_class.from_toml(bad)
      expect(m.valid?).to be(false)
      expect(m.validate).to include(/unsupported manifest version/)
    end
  end
end
