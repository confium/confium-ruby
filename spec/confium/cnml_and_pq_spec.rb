# frozen_string_literal: true

require "confium"

# Verifies TODO.completion/024-cnml-certificate-profile.md and
# TODO.completion/021-pq-signature-verification.md
RSpec.describe "CNML profile + PQ verifier docs" do
  it "CNML module has required extension OIDs" do
    require "confium/pki/cnml"
    expect(Confium::PKI::CNML::REQUIRED_EXTENSIONS).to include("2.5.29.19")
    expect(Confium::PKI::CNML::REQUIRED_EXTENSIONS).to include("2.5.29.14")
  end

  it "CNML has cert roles" do
    require "confium/pki/cnml"
    roles = Confium::PKI::CNML.cert_roles
    expect(roles).to include(:manufacturer, :testing_lab, :biml_director)
  end

  it "CNML missing_extensions returns array" do
    require "confium/pki/cnml"
    result = Confium::PKI::CNML.missing_extensions(nil)
    expect(result).to be_a(Array)
  end

  it "Policy has FIPS mode toggle" do
    Confium::Policy.fips_mode = true
    expect(Confium::Policy.fips_mode).to be(true)
    expect(Confium::Policy.jurisdiction).to eq(:us)
    Confium::Policy.reset!
  end

  it "Composite supports caller-supplied ML-DSA verifier" do
    component = {
      "algorithm"  => "ML-DSA-65",
      "public_key" => [0] * 1952,
      "signature"  => [0] * 3309,
    }
    sig = Confium::Composite::Signature.new([component])
    result = sig.verify("test", { "ML-DSA-65" => ->(_, _, _) { true } })
    expect(result.all_verified?).to be(true)
  ensure
    Confium::Policy.reset!
  end
end
