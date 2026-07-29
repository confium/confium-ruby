# frozen_string_literal: true

require "confium"
require "confium/pki/certificate_builder"
require "confium/pki/cms/signed_data_builder"
require "confium/tc/session_stub"
require "confium/transparency/ots"

RSpec.describe Confium::PKI::CertificateBuilder do
  it "builds a self-signed Ed25519 cert metadata" do
    kp = Confium::Composite.generate_ed25519_keypair
    builder = described_class.new
    builder.subject = "/CN=test"
    result = builder.build_self_signed(algorithm: :ed25519, private_key: kp["private_key"])
    expect(result[:subject]).to eq("/CN=test")
    expect(result[:algorithm]).to eq("ed25519")
    expect(result[:public_key_hex]).to match(/\A[0-9a-f]+\z/)
  end
end

RSpec.describe Confium::PKI::CMS::SignedDataBuilder do
  it "builds a CMS envelope with one Ed25519 signer" do
    kp = Confium::Composite.generate_ed25519_keypair
    builder = described_class.new
    builder.content = "hello".b
    # Real SubjectKeyIdentifier extraction requires at least 20 bytes
    # (RFC 5652 §5.3 SKI convention). Use a realistic-sized fake cert.
    fake_cert = ("\x30\x82\x01\x00" + "C" * 256).b
    builder.add_signer(cert_der: fake_cert, private_key: kp["private_key"], algorithm: :ed25519)
    sd = builder.build
    expect(sd).to be_a(Confium::PKI::CMS::SignedData)
    expect(sd.signer_count).to eq(1)
  end
end

RSpec.describe Confium::TC::SessionStub do
  it "tracks round progression" do
    session = described_class.new(scheme: "frost-ed25519", threshold: 3, party_count: 5, this_party_idx: 0)
    expect(session.round).to eq(0)
    expect(session.complete?).to be(false)
    session.round_step([])
    session.round_step([])
    session.round_step([])
    expect(session.complete?).to be(true)
  end
end

RSpec.describe Confium::Transparency::OTS do
  it "has calendar server constants" do
    expect(Confium::Transparency::OTS::DEFAULT_CALENDARS).to include("https://a.pool.opentimestamps.org")
  end

  it "stamp returns nil (network stub)" do
    expect(Confium::Transparency::OTS.stamp("\x00" * 32)).to be_nil
  end
end
