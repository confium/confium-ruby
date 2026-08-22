# frozen_string_literal: true

require 'confium'

RSpec.describe Confium::Attributes do
  describe '.parse' do
    it 'returns a Predicate instance' do
      pred = described_class.parse('min_count("role:director", 3)')
      expect(pred).to be_a(described_class::Predicate)
    end

    it 'raises on a malformed expression' do
      expect do
        described_class.parse('not_a_function(')
      end.to raise_error(Confium::ParseError)
    end

    it 'accepts shallow nesting (32 levels or below)' do
      # 30 levels of `not(...)` wraps `any("x")`. Within the
      # binding's depth budget.
      expr = 'any("x")'
      30.times { expr = "not(#{expr})" }
      expect { described_class.parse(expr) }.not_to raise_error
    end

    it 'rejects deep nesting (over MAX_DSL_DEPTH = 32)' do
      expr = 'any("x")'
      100.times { expr = "not(#{expr})" }
      expect { described_class.parse(expr) }.to raise_error(Confium::ParseError, /recursion depth/i)
    end
  end

  describe Confium::Attributes::Signer do
    it 'starts empty and reports has?/values correctly' do
      s = described_class.new
      expect(s.has?('role:director')).to be(false)
      s.add('role:director', 'yes')
      expect(s.has?('role:director')).to be(true)
      expect(s.values('role:director')).to eq(['yes'])
    end
  end

  describe Confium::Attributes::Predicate do
    def signer(role: nil, region: nil, **extra)
      s = Confium::Attributes::Signer.new
      s.add('role:director', 'yes') if role
      s.add('region', region) if region
      extra.each { |k, v| s.add(k.to_s, v) }
      s
    end

    let(:alice)   { signer(role: true, region: 'europe') }
    let(:bob)     { signer(role: true, region: 'americas') }
    let(:carol)   { signer(role: true, region: 'asia-pacific') }
    let(:non_dir) { signer(region: 'europe') }

    it 'min_count succeeds when threshold is met' do
      pred = Confium::Attributes.parse('min_count("role:director", 3)')
      expect(pred.satisfied_by?([alice, bob, carol])).to be(true)
    end

    it 'min_count fails when threshold is not met' do
      pred = Confium::Attributes.parse('min_count("role:director", 3)')
      expect(pred.satisfied_by?([alice, bob])).to be(false)
    end

    it 'min_distinct requires N distinct values' do
      pred = Confium::Attributes.parse('min_distinct("region", 3)')
      expect(pred.satisfied_by?([alice, bob, carol])).to be(true)
      expect(pred.satisfied_by?([alice, bob, alice])).to be(false)
    end

    it 'any requires at least one signer with the attribute' do
      pred = Confium::Attributes.parse('any("role:director")')
      expect(pred.satisfied_by?([non_dir, alice])).to be(true)
      expect(pred.satisfied_by?([non_dir])).to be(false)
    end

    it 'all requires every signer to have the attribute' do
      pred = Confium::Attributes.parse('all("role:director")')
      expect(pred.satisfied_by?([alice, bob])).to be(true)
      expect(pred.satisfied_by?([alice, non_dir])).to be(false)
    end

    it 'none requires no signer to have the attribute' do
      pred = Confium::Attributes.parse('none("nationality:cn")')
      expect(pred.satisfied_by?([alice, bob])).to be(true)
      blocked = signer('nationality:cn': 'yes')
      expect(pred.satisfied_by?([alice, blocked])).to be(false)
    end

    it 'composes via and/or/not' do
      pred = Confium::Attributes.parse(
        'and(min_count("role:director", 3), min_distinct("region", 3))'
      )
      expect(pred.satisfied_by?([alice, bob, carol])).to be(true)

      pred_or = Confium::Attributes.parse(
        'or(min_count("role:director", 5), any("region"))'
      )
      expect(pred_or.satisfied_by?([alice])).to be(true)

      pred_not = Confium::Attributes.parse(
        'not(any("nationality:cn"))'
      )
      expect(pred_not.satisfied_by?([alice, bob])).to be(true)
    end
  end
end
