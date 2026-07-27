# frozen_string_literal: true

require "confium"
require "fileutils"

RSpec.describe Confium::PKI::PathValidator do
  before(:all) do
    support_dir = File.expand_path("support", __dir__)
    FileUtils.mkdir_p(support_dir)
    @pem_path = File.join(support_dir, "test.pem")
    unless File.exist?(@pem_path)
      system(
        "openssl req -x509 -newkey rsa:2048 -nodes " \
        "-keyout /dev/null -out #{@pem_path} -days 365 " \
        "-subj '/CN=Test CA'",
        out: "/dev/null", err: "/dev/null"
      ) or raise "openssl failed"
    end
  end

  let(:cert) { Confium::PKI::Certificate.from_pem(File.read(@pem_path)) }

  it "validates a self-signed cert as its own root" do
    result = described_class.validate(cert, nil, cert, Time.now.utc.iso8601)
    expect(result).to be_a(Confium::PKI::PathValidationResult)
    expect(result.valid?).to be(true)
  end

  it "returns check_count" do
    result = described_class.validate(cert, nil, cert)
    expect(result.check_count).to be_a(Integer)
  end

  it "accepts nil intermediates" do
    result = described_class.validate(cert, nil, cert)
    expect(result.valid?).to be(true)
  end
end

RSpec.describe Confium::Audit do
  after { described_class.sink = nil }

  it "is disabled by default" do
    expect(described_class.enabled?).to be(false)
  end

  it "enables when a sink Proc is set" do
    described_class.sink = ->(_) {}
    expect(described_class.enabled?).to be(true)
  end

  it "records audit entries through the sink" do
    records = []
    described_class.sink = ->(r) { records << r }
    described_class.record("sign", "hash123", "success", "alice", "Ed25519", nil)
    expect(records.size).to eq(1)
    expect(records[0]["operation"]).to eq("sign")
    expect(records[0]["actor"]).to eq("alice")
    expect(records[0]["result"]).to eq("success")
  end

  it "disables when sink is set to nil" do
    described_class.sink = ->(_) {}
    described_class.sink = nil
    expect(described_class.enabled?).to be(false)
  end
end
