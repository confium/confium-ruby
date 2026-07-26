# frozen_string_literal: true

require_relative "spec_helper"

RSpec.describe Confium do
  describe "VERSION" do
    it "is defined" do
      expect(Confium::VERSION).not_to be_nil
    end

    it "is a string" do
      expect(Confium::VERSION).to be_a(String)
    end

    it "follows semver format" do
      expect(Confium::VERSION).to match(/^\d+\.\d+\.\d+/)
    end
  end

  describe "module structure" do
    it "defines Confium as a module" do
      expect(Confium).to be_a(Module)
    end

    it "autoloads FFI on first reference" do
      expect { Confium::FFI }.not_to raise_error
    end

    it "autoloads Lib on first reference" do
      expect { Confium::Lib }.not_to raise_error
    end

    it "autoloads CFM on first reference" do
      expect { Confium::CFM }.not_to raise_error
    end

    it "autoloads Digest on first reference" do
      expect { Confium::Digest }.not_to raise_error
    end

    it "autoloads Crypto on first reference" do
      expect { Confium::Crypto }.not_to raise_error
    end
  end

  describe ".call_ffi_rc" do
    it "is defined as a class method" do
      expect(Confium.respond_to?(:call_ffi_rc)).to be(true)
    end
  end

  describe ".call_ffi" do
    it "is defined as a class method" do
      expect(Confium.respond_to?(:call_ffi)).to be(true)
    end
  end
end
