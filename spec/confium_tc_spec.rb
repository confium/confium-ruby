# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe Confium::TC do
  it "autoloads TC module on first reference" do
    expect { Confium::TC }.not_to raise_error
    expect(Confium::TC).to be_a(Module)
  end

  it "autoloads TC::Session on first reference" do
    expect { Confium::TC::Session }.not_to raise_error
  end

  it "autoloads TC::Coordinator on first reference" do
    expect { Confium::TC::Coordinator }.not_to raise_error
  end
end

RSpec.describe Confium::TC::Session do
  let(:session) do
    Confium::TC::Session.new(
      scheme: "FROST-ed25519",
      threshold: 3,
      num_parties: 5,
      party_index: 0,
    )
  end

  describe "#initialize" do
    it "stores session parameters" do
      expect(session.scheme).to eq("FROST-ed25519")
      expect(session.threshold).to eq(3)
      expect(session.num_parties).to eq(5)
      expect(session.party_index).to eq(0)
    end

    it "starts in pending state" do
      expect(session.state).to eq(:pending)
    end
  end

  describe "#set_local_share" do
    it "accepts a string share" do
      expect { session.set_local_share("share-bytes") }.not_to raise_error
    end

    it "rejects non-string share" do
      expect { session.set_local_share(123) }.to raise_error(ArgumentError)
    end
  end

  describe "#complete?" do
    it "returns false for new session" do
      expect(session.complete?).to be(false)
    end
  end

  describe "#result" do
    it "raises when not complete" do
      expect { session.result }.to raise_error(RuntimeError)
    end
  end
end

RSpec.describe Confium::TC::Coordinator do
  let(:coordinator) { Confium::TC::Coordinator.new(quorum_id: "test-quorum") }

  describe "#initialize" do
    it "stores quorum ID" do
      expect(coordinator.quorum_id).to eq("test-quorum")
    end

    it "starts with no sessions" do
      expect(coordinator.sessions).to be_empty
    end
  end

  describe "#create_session" do
    it "creates and returns a session ID" do
      id = coordinator.create_session(message: "data", threshold: 2)
      expect(id).to start_with("session-")
      expect(coordinator.sessions).to include(id)
    end

    it "stores session parameters" do
      id = coordinator.create_session(message: "data", threshold: 3, unlock_window: 7200)
      session = coordinator.sessions[id]
      expect(session[:threshold]).to eq(3)
      expect(session[:unlock_window]).to eq(7200)
    end
  end

  describe "#submit_commitment" do
    it "stores commitment and transitions to commitments_collected when threshold met" do
      id = coordinator.create_session(message: "data", threshold: 2)
      coordinator.submit_commitment(id, "alice", "commitment-1")
      expect(coordinator.session_state(id)).to eq(:pending)
      coordinator.submit_commitment(id, "bob", "commitment-2")
      expect(coordinator.session_state(id)).to eq(:commitments_collected)
    end
  end

  describe "#aggregate" do
    it "raises when threshold not met" do
      id = coordinator.create_session(message: "data", threshold: 2)
      coordinator.submit_commitment(id, "alice", "c1")
      coordinator.submit_commitment(id, "bob", "c2")
      expect { coordinator.aggregate(id) }.to raise_error(RuntimeError, /Threshold not met/)
    end

    it "completes when threshold met" do
      id = coordinator.create_session(message: "data", threshold: 2)
      coordinator.submit_commitment(id, "alice", "c1")
      coordinator.submit_commitment(id, "bob", "c2")
      coordinator.submit_share(id, "alice", "s1")
      coordinator.submit_share(id, "bob", "s2")
      result = coordinator.aggregate(id)
      expect(result).to eq("s1s2")
      expect(coordinator.session_state(id)).to eq(:completed)
    end
  end

  describe "#session_state" do
    it "returns nil for unknown session" do
      expect(coordinator.session_state("nonexistent")).to be_nil
    end
  end
end
