# frozen_string_literal: true

require 'spec_helper'

# 642-bit primes give N > q^5 + q^2 (~2^1282): the minimum for an
# honest run where shares never wrap mod N (see spec 70-cmp20).
# Safe-prime search takes seconds — one keypair shared across the
# suite, mirroring the upstream crate's test fixtures. The keypair
# plays the INITIATOR: the exchange runs under its key end to end.
MTA_KEYPAIR = Confium::TC::Cmp20::Mta.generate_keypair(642).freeze
MTA_CK_I = Confium::TC::Cmp20::Mta.generate_commitment_key(64).freeze
MTA_CK_J = Confium::TC::Cmp20::Mta.generate_commitment_key(64).freeze
MTA_Q = Confium::TC::Cmp20::Mta::P256_ORDER
MTA_K_I = '2a'
MTA_X_J = '1b3'

RSpec.describe Confium::TC::Cmp20::Mta do
  def product_mod_q
    (MTA_K_I.to_i(16) * MTA_X_J.to_i(16)) % MTA_Q.to_i(16)
  end

  def run_split(k_hex = MTA_K_I)
    msg1 = described_class.party_i_init(MTA_KEYPAIR['public'], MTA_CK_J, MTA_Q, k_hex)
    msg2, beta = described_class.party_j_respond(
      MTA_KEYPAIR['public'], MTA_CK_I, MTA_CK_J, MTA_Q, msg1, MTA_X_J
    )
    alpha = described_class.party_i_finish(
      MTA_KEYPAIR['public'], MTA_KEYPAIR['private'], MTA_CK_I, MTA_Q, msg1['ciphertext'], msg2
    )
    [alpha, beta, msg1, msg2]
  end

  describe '.full' do
    it 'returns shares that subtract to the product mod q' do
      alpha, beta = described_class.full(
        MTA_KEYPAIR['public'], MTA_KEYPAIR['private'], MTA_CK_I, MTA_CK_J, MTA_Q, MTA_K_I, MTA_X_J
      )
      expect((alpha.to_i(16) - beta.to_i(16)) % MTA_Q.to_i(16)).to eq(product_mod_q)
    end

    it 'hides the product from either share alone' do
      alpha, beta = described_class.full(
        MTA_KEYPAIR['public'], MTA_KEYPAIR['private'], MTA_CK_I, MTA_CK_J, MTA_Q, MTA_K_I, MTA_X_J
      )
      product = MTA_K_I.to_i(16) * MTA_X_J.to_i(16)
      expect(alpha.to_i(16)).not_to eq(product)
      expect(beta.to_i(16)).not_to eq(product)
    end
  end

  describe 'the three proved rounds' do
    it 'compose to the same share contract as .full' do
      alpha, beta, = run_split
      expect((alpha.to_i(16) - beta.to_i(16)) % MTA_Q.to_i(16)).to eq(product_mod_q)
    end

    it 'serializes messages as Hashes of hex integers' do
      _, _, msg1, msg2 = run_split
      expect(msg1).to include('ciphertext' => kind_of(String), 'range_proof' => kind_of(Hash))
      expect(msg1['range_proof'].keys.sort).to eq(%w[s s1 s2 u w z])
      expect(msg2['respondent_proof'].keys.sort).to eq(%w[s s1 s2 t t1 t2 v w z z_prime])
      [msg1['ciphertext'], msg2['ciphertext'], msg2['beta']].each do |hex|
        expect(hex).to match(/\A\h+\z/)
      end
    end
  end

  describe 'the responder side' do
    it 'needs no private material — the exchange runs under the initiator key' do
      msg1 = described_class.party_i_init(MTA_KEYPAIR['public'], MTA_CK_J, MTA_Q, MTA_K_I)
      # Public halves only: party j operates on ciphertext it can never open.
      expect do
        described_class.party_j_respond(
          MTA_KEYPAIR['public'], MTA_CK_I, MTA_CK_J, MTA_Q, msg1, MTA_X_J
        )
      end.not_to raise_error
    end
  end

  describe 'forgery rejection' do
    it 'rejects a tampered response ciphertext' do
      _, _, msg1, msg2 = run_split
      tampered = msg2.merge('ciphertext' => (msg2['ciphertext'].to_i(16) ^ 1).to_s(16))
      expect do
        described_class.party_i_finish(
          MTA_KEYPAIR['public'], MTA_KEYPAIR['private'], MTA_CK_I, MTA_Q, msg1['ciphertext'], tampered
        )
      end.to raise_error(Confium::TC::Cmp20::MtaError, /proof/i)
    end

    it 'rejects a proof replayed against a different statement' do
      _, _, msg1, = run_split
      other = described_class.party_i_init(MTA_KEYPAIR['public'], MTA_CK_J, MTA_Q, '7')
      msg2, = described_class.party_j_respond(
        MTA_KEYPAIR['public'], MTA_CK_I, MTA_CK_J, MTA_Q, msg1, MTA_X_J
      )
      expect do
        described_class.party_i_finish(
          MTA_KEYPAIR['public'], MTA_KEYPAIR['private'], MTA_CK_I, MTA_Q, other['ciphertext'], msg2
        )
      end.to raise_error(Confium::TC::Cmp20::MtaError, /proof/i)
    end
  end

  describe '.generate_keypair' do
    it 'returns hex-encoded public and private halves' do
      expect(MTA_KEYPAIR['public'].keys.sort).to eq(%w[g n n_squared])
      expect(MTA_KEYPAIR['private'].keys.sort).to eq(%w[lambda mu])
      expect(MTA_KEYPAIR['public']['n']).to match(/\A[1-9a-f]\h+\z/)
    end

    it 'bounds prime_bits' do
      expect { described_class.generate_keypair(8) }
        .to raise_error(ArgumentError, /prime_bits/)
    end
  end

  describe '.generate_commitment_key' do
    it 'returns the Strong-RSA commitment triple' do
      expect(MTA_CK_I.keys.sort).to eq(%w[h1 h2 n_tilde])
    end
  end

  describe 'input validation' do
    it 'rejects non-hex secrets' do
      expect { described_class.party_i_init(MTA_KEYPAIR['public'], MTA_CK_J, MTA_Q, 'zz') }
        .to raise_error(ArgumentError, /hex/)
    end

    it 'rejects a missing public-key field' do
      broken = MTA_KEYPAIR['public'].except('g')
      expect { described_class.party_i_init(broken, MTA_CK_J, MTA_Q, MTA_K_I) }
        .to raise_error(ArgumentError, /g/)
    end
  end
end
