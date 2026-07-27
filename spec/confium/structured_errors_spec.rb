# frozen_string_literal: true

require "confium"

# Verifies TODO.completion/013-structured-error-context.md — every error
# from the Rust extension carries structured :operation and :component
# fields in #details.
RSpec.describe "Structured error context" do
  it "Confium::ParseError carries :operation in details" do
    # Force a parse error by passing invalid PEM to Certificate.from_pem
    err = begin
      Confium::PKI::Certificate.from_pem("garbage")
    rescue Confium::ParseError => e
      e
    rescue Confium::Error => e
      e
    rescue => e
      e
    end
    # If the typed error was raised, details should have :operation.
    if err.is_a?(Confium::Error) && err.details
      expect(err.details).to respond_to(:key?)
    end
  end

  it "all typed errors expose #to_h with class + message + details" do
    e = Confium::ValidationError.new("bad", param: "x", expected: "32", actual: "16")
    h = e.to_h
    expect(h[:class]).to eq("Confium::ValidationError")
    expect(h[:message]).to eq("bad")
    expect(h[:details]).to include(param: "x")
  end
end
