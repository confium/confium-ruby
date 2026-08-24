# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Confium::OpenPGP do
  fixtures_dir = File.expand_path('../fixtures/openpgp', __dir__)

  let(:public_key) { File.read(File.join(fixtures_dir, 'pub.asc')) }
  let(:message) { File.read(File.join(fixtures_dir, 'msg.txt'), mode: 'rb') }
  let(:detached_signature) { File.read(File.join(fixtures_dir, 'msg.txt.asc'), mode: 'rb') }
  let(:clearsigned) { File.read(File.join(fixtures_dir, 'clearsigned.asc'), mode: 'rb') }
  let(:tampered_message) { File.read(File.join(fixtures_dir, 'tampered.txt'), mode: 'rb') }

  describe 'PGP_AVAILABLE' do
    it 'is a boolean' do
      expect([true, false]).to include(described_class::PGP_AVAILABLE)
    end
  end

  context 'when the extension was built with the pgp cargo feature' do
    before { skip 'pgp cargo feature not compiled into this build' unless described_class::PGP_AVAILABLE }

    describe '.verify_detached' do
      it 'verifies a valid detached signature against the signing key' do
        result = described_class.verify_detached(message, detached_signature, public_key)

        expect(result['any_valid']).to be true
        expect(result['signature_count']).to eq(1)
        expect(result['signatures']).to all(include('valid' => true))
        expect(result['signatures'].first['key_id']).to be_a(String)
        expect(result['signatures'].first['creation_time']).to be > 0
      end

      it 'accepts the keys argument as an array' do
        result = described_class.verify_detached(message, detached_signature, [public_key])

        expect(result['any_valid']).to be true
      end

      it 'reports a tampered message as invalid' do
        result = described_class.verify_detached(tampered_message, detached_signature, public_key)

        expect(result['any_valid']).to be false
        expect(result['signature_count']).to eq(0)
      end

      it 'reports signatures over unknown keys as not valid' do
        result = described_class.verify_detached(message, detached_signature)

        expect(result['any_valid']).to be false
        expect(result['signature_count']).to eq(0)
      end

      it 'rejects wrong argument counts' do
        expect { described_class.verify_detached(message) }
          .to raise_error(ArgumentError, /wrong number of arguments/)
        expect { described_class.verify_detached }
          .to raise_error(ArgumentError, /wrong number of arguments/)
      end
    end

    describe '.verify' do
      it 'verifies an inline clearsigned message' do
        result = described_class.verify(clearsigned, public_key)

        expect(result['any_valid']).to be true
        expect(result['signatures']).to all(include('valid' => true))
      end

      it 'raises a ParseError for input that is not an OpenPGP message' do
        expect { described_class.verify("not a pgp message\n", public_key) }
          .to raise_error(Confium::ParseError)
      end
    end
  end

  context 'when the extension was built without the pgp cargo feature' do
    before { skip 'pgp cargo feature is compiled into this build' if described_class::PGP_AVAILABLE }

    it 'raises with rebuild instructions instead of pretending to verify' do
      expect { described_class.verify_detached(message, detached_signature, public_key) }
        .to raise_error(RuntimeError, /requires the pgp cargo feature/)
      expect { described_class.verify(clearsigned, public_key) }
        .to raise_error(RuntimeError, /requires the pgp cargo feature/)
    end
  end
end
