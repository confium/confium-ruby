# frozen_string_literal: true

require "confium"

# Verifies TODO.completion/005-composite-verifier-callback.md —
# Confium::Composite::Signature#verify accepts a Hash of caller-supplied
# verifiers keyed by algorithm string, used for algorithms Confium
# doesn't support natively (e.g. ML-DSA-65 until a Rust crate ships).
RSpec.describe "Confium::Composite caller-supplied verifier callback" do
  it "accepts a verifiers: keyword arg with a Proc per algorithm" do
    # Build a fake composite signature whose components claim a custom
    # algorithm name. Confium has no built-in verifier for it, so the
    # caller supplies one.
    component = {
      "algorithm"  => "Custom-X",
      "public_key" => "pk-bytes",
      "signature"  => "sig-bytes",
    }
    sig = Confium::Composite::Signature.new([component])

    saw_args = nil
    verifiers = {
      "Custom-X" => ->(pk, msg, s) {
        saw_args = [pk, msg, s]
        true
      },
    }
    result = sig.verify("the message", verifiers)
    expect(result).to be_a(Confium::Composite::VerificationResult)
    expect(result.all_verified?).to be(true)
    expect(saw_args[0]).to eq("pk-bytes".bytes)   # Vec<u8> -> Array<Integer>
    expect(saw_args[1]).to eq("the message".bytes)
    expect(saw_args[2]).to eq("sig-bytes".bytes)
  end

  it "reports per-component failure when the callback returns false" do
    component = {
      "algorithm"  => "Custom-Y",
      "public_key" => "pk",
      "signature"  => "sig",
    }
    sig = Confium::Composite::Signature.new([component])
    verifiers = { "Custom-Y" => ->(_, _, _) { false } }
    result = sig.verify("msg", verifiers)
    expect(result.all_verified?).to be(false)
    expect(result.per_component.size).to eq(1)
    expect(result.per_component[0]["verified"]).to be(false)
  end

  it "still uses built-in Ed25519 verifier when no callback supplied" do
    kp = Confium::Composite.generate_ed25519_keypair
    component = Confium::Composite.sign_ed25519(kp["private_key"], "hello")
    sig = Confium::Composite::Signature.new([component])
    # No verifiers: kwarg — built-in Ed25519 verifier should run.
    result = sig.verify("hello")
    expect(result.all_verified?).to be(true)
  end

  it "uses caller verifier for unknown algorithm even with built-ins present" do
    # Mixed composite: Ed25519 (built-in) + Custom (caller).
    kp = Confium::Composite.generate_ed25519_keypair
    ed = Confium::Composite.sign_ed25519(kp["private_key"], "msg")
    custom = {
      "algorithm"  => "Custom",
      "public_key" => "x",
      "signature"  => "y",
    }
    sig = Confium::Composite::Signature.new([ed, custom])
    verifiers = { "Custom" => ->(_, _, _) { true } }
    result = sig.verify("msg", verifiers)
    expect(result.all_verified?).to be(true)
    expect(sig.algorithms).to eq(["Ed25519", "Custom"])
  end
end
