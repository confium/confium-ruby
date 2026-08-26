# frozen_string_literal: true

require 'confium'
require 'tmpdir'

RSpec.describe Confium::Store::Keystore do
  describe '.new' do
    it 'opens a registered backend by wire name' do
      expect(described_class.new('memory')).to be_a(described_class)
    end

    it 'passes backend options through' do
      Dir.mktmpdir do |dir|
        ks = described_class.new('filesystem', { 'path' => dir })
        expect(ks).to be_a(described_class)
      end
    end

    it 'raises a typed Confium::Error naming an unknown backend' do
      expect { described_class.new('nope') }
        .to raise_error(Confium::Error, /Unknown backend/)
    end
  end

  describe '#sign' do
    let(:ks) { described_class.new('memory') }

    it 'raises a typed error on backends without remote signing' do
      error = nil
      begin
        ks.sign('key-1', 'ECDSA_SHA_256', 'message')
      rescue Confium::Error => e
        error = e
      end

      expect(error).not_to be_nil
      expect(error.message).to match(/not support remote signing/)
      expect(error.details[:operation]).to eq('Keystore#sign')
      expect(error.details[:what]).to include('remote signing')
    end
  end

  describe 'Confium::Store.backends' do
    it 'lists the registered wire names' do
      expect(Confium::Store.backends).to include('memory')
    end
  end
end
