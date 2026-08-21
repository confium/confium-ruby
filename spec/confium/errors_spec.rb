# frozen_string_literal: true

require 'confium'

# Verifies TODO.completion/001-typed-error-hierarchy.md — the typed
# Confium error classes with structured details.
RSpec.describe 'Confium typed error hierarchy' do
  it 'all subclasses inherit from Confium::Error' do
    expect(Confium::ParseError).to be < Confium::Error
    expect(Confium::ValidationError).to be < Confium::Error
    expect(Confium::VerificationError).to be < Confium::Error
    expect(Confium::ThresholdError).to be < Confium::Error
    expect(Confium::CryptoError).to be < Confium::Error
    expect(Confium::NotFoundError).to be < Confium::Error
    expect(Confium::UnresolvedSignerError).to be < Confium::Error
    expect(Confium::PolicyViolationError).to be < Confium::Error
  end

  describe Confium::Error do
    it 'exposes #details as a Hash' do
      e = described_class.new('boom', details: { foo: 1 })
      expect(e.details).to eq(foo: 1)
    end

    it 'exposes #to_h for JSON logging' do
      e = described_class.new('boom', details: { foo: 1 })
      expect(e.to_h).to include(class: 'Confium::Error', message: 'boom')
    end
  end

  describe Confium::ParseError do
    it 'exposes :format and :offset' do
      e = described_class.new('bad json', format: :json, offset: 42)
      expect(e.format).to eq(:json)
      expect(e.offset).to eq(42)
      expect(e.details).to include(format: :json, offset: 42)
    end
  end

  describe Confium::ValidationError do
    it 'exposes :param, :expected, :actual' do
      e = described_class.new('too small', param: :secret, expected: 32, actual: 16)
      expect(e.param).to eq(:secret)
      expect(e.expected).to eq(32)
      expect(e.actual).to eq(16)
    end
  end

  describe Confium::VerificationError do
    it 'exposes :signer_index and :algorithm' do
      e = described_class.new('sig bad', signer_index: 2, algorithm: 'Ed25519')
      expect(e.signer_index).to eq(2)
      expect(e.algorithm).to eq('Ed25519')
    end
  end

  describe Confium::ThresholdError do
    it 'exposes :have_count and :need_count' do
      e = described_class.new('insufficient', have_count: 2, need_count: 3)
      expect(e.have_count).to eq(2)
      expect(e.need_count).to eq(3)
    end
  end

  describe Confium::CryptoError do
    it 'exposes :primitive' do
      e = described_class.new('bad scalar', primitive: :p256)
      expect(e.primitive).to eq(:p256)
    end
  end

  describe Confium::NotFoundError do
    it 'exposes :kind and :identifier' do
      e = described_class.new('no slot', kind: :share, identifier: 5)
      expect(e.kind).to eq(:share)
      expect(e.identifier).to eq(5)
    end
  end

  describe Confium::IndexError do
    it 'exposes :index and :valid_range' do
      e = described_class.new('oob', index: 99, valid_range: 0..9)
      expect(e.index).to eq(99)
      expect(e.valid_range).to eq(0..9)
    end
  end

  describe Confium::UnresolvedSignerError do
    it 'exposes :signer_index' do
      e = described_class.new('no cert', signer_index: 3)
      expect(e.signer_index).to eq(3)
    end
  end

  describe Confium::PolicyViolationError do
    it 'exposes :policy and :violation' do
      e = described_class.new('no rsa1024', policy: :eu, violation: :weak_algorithm)
      expect(e.policy).to eq(:eu)
      expect(e.violation).to eq(:weak_algorithm)
    end
  end

  it 'rescue Confium::Error catches a specific subclass' do
    raise Confium::ParseError, 'bad'
  rescue Confium::Error => e
    expect(e).to be_a(Confium::ParseError)
  end
end
