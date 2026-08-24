# frozen_string_literal: true

require 'confium'

RSpec.describe Confium::NativeWindows do
  describe '.candidates' do
    # Exact-minor-only lines: 3.1 and 3.2 broke their predecessors'
    # ABI (object shapes; the VM pointer rb-sys references), and 4.0
    # must not fall back across the major line.
    {
      '3.0.7' => ['3.0'],
      '3.1.6' => ['3.1'],
      '3.2.8' => ['3.2'],
      '4.0.0' => ['4.0'],
      '4.0.2' => ['4.0'],
      '4.1.0' => ['4.1']
    }.each do |version, expected|
      it "returns exactly #{expected.inspect} on #{version}" do
        expect(described_class.candidates(version)).to eq(expected)
      end
    end

    # 3.3-window binaries load on 3.3 and 3.4 (no VM-pointer export,
    # no object-shape break) — but only within the 3.x line.
    {
      '3.3.0' => ['3.3'],
      '3.3.8' => ['3.3'],
      '3.4.0' => %w[3.4 3.3],
      '3.4.8' => %w[3.4 3.3]
    }.each do |version, expected|
      it "returns #{expected.inspect} on #{version}" do
        expect(described_class.candidates(version)).to eq(expected)
      end
    end

    it 'rejects strings that are not ruby versions' do
      expect { described_class.candidates('pancakes') }
        .to raise_error(ArgumentError, /not a ruby version/)
    end

    it 'never proposes a cross-major fallback for 4.x' do
      (4..6).each do |minor|
        expect(described_class.candidates("4.#{minor}.0")).to eq(["4.#{minor}"])
      end
    end
  end
end
