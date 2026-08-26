# frozen_string_literal: true

require 'confium'

RSpec.describe Confium::TC::Session do
  # RuboCop forbids constants inside describe blocks; let-variables
  # work everywhere the constants did.
  let(:parties) { %w[p0 p1 p2] }
  let(:threshold) { 2 }
  let(:message) { 'per-party protocol test' }

  # Broadcast router: runs every party's round, collects each party's
  # outgoing messages, and hands each party the messages from everyone
  # else (the multi-host topology, in memory).
  def run_protocol(sessions)
    inbox = Array.new(sessions.length) { [] }
    until sessions.all?(&:complete?)
      outgoing = []
      sessions.each_with_index do |session, i|
        result = session.round_step(inbox[i])
        result['outgoing'].each { |m| outgoing << m }
      end
      break if outgoing.empty?

      inbox = Array.new(sessions.length) do |i|
        outgoing.reject { |m| m['from'] == parties[i] }
      end
    end
    sessions
  end

  # DKG output: [u32 pubkey_len][pubkey][u32 share_len][share].
  def parse_dkg_output(blob)
    pub_len = blob[0, 4].unpack1('N')
    pubkey = blob[4, pub_len]
    share = blob[4 + pub_len + 4, blob[4 + pub_len + 4, 4].unpack1('N')]
    [pubkey, share]
  end

  describe 'FROST-ed25519-dkg' do
    it 'runs a 3-party DKG where every party derives the same public key' do
      sessions = parties.each_index.map do |i|
        described_class.new(
          'FROST-ed25519-dkg',
          parties: parties, threshold: threshold, this_party_idx: i
        )
      end

      run_protocol(sessions)
      expect(sessions).to all(be_complete)

      outputs = sessions.map { |s| parse_dkg_output(s.result) }
      pubkeys = outputs.map(&:first)
      expect(pubkeys.uniq.length).to eq(1)
      expect(pubkeys.first.bytesize).to eq(32)
      outputs.each { |(_, share)| expect(share.bytesize).to eq(32) }
    end

    it 'rejects an unknown scheme with a typed error' do
      expect do
        described_class.new('NOPE', parties: parties, threshold: 2, this_party_idx: 0)
      end.to raise_error(Confium::Error, /NOPE/)
    end
  end

  describe 'FROST-ed25519 signing' do
    it 'produces identical RFC-8032 signatures on every signing party' do
      dkg = parties.each_index.map do |i|
        described_class.new(
          'FROST-ed25519-dkg',
          parties: parties, threshold: threshold, this_party_idx: i
        )
      end
      run_protocol(dkg)
      # The signing session's local_share is the party's FULL DKG output
      # blob — it embeds the group public key, which FROST needs for the
      # challenge and cannot derive from the bare scalar.
      blobs = dkg.map(&:result)
      group_pubkey = parse_dkg_output(blobs.first).first

      signers = [0, 1].map do |i|
        described_class.new(
          'FROST-ed25519',
          parties: parties, threshold: threshold, this_party_idx: i,
          local_share: blobs[i], message: message
        )
      end
      run_protocol(signers)
      expect(signers).to all(be_complete)

      signatures = signers.map(&:result)
      expect(signatures).to all(be == signatures.first)
      expect(signatures.first.bytesize).to eq(64)

      # RFC-8032 verify under the group public key via the composite
      # Ed25519 verifier.
      component = {
        'algorithm' => 'Ed25519',
        'public_key' => group_pubkey,
        'signature' => signatures.first
      }
      result = Confium::Composite::Signature.new([component]).verify(message)
      expect(result.all_verified?).to be(true)
    end
  end

  describe 'accessors' do
    it 'exposes the session parameters' do
      session = described_class.new(
        'FROST-ed25519-dkg',
        parties: parties, threshold: threshold, this_party_idx: 1
      )
      expect(session.scheme_name).to eq('FROST-ed25519-dkg')
      expect(session.threshold).to eq(threshold)
      expect(session.party_count).to eq(3)
      expect(session.this_party_idx).to eq(1)
      expect(session.round).to eq(0)
      expect(session.complete?).to be(false)
    end
  end
end
