# frozen_string_literal: true

require "confium"

RSpec.describe "Confium::Audit::MemorySink Enumerable mixin" do
  let(:sink) { Confium::Audit::MemorySink.new }

  before do
    sink.write("operation" => "composite_sign", "result" => "success", "actor" => "alice")
    sink.write("operation" => "composite_sign", "result" => "failure", "actor" => "bob")
    sink.write("operation" => "cms_verify",      "result" => "success", "actor" => "alice")
    sink.write("operation" => "tc_sign",         "result" => "success", "actor" => "carol")
  end

  it "supports #select via Enumerable" do
    failures = sink.select { |r| r["result"] == "failure" }
    expect(failures.length).to eq(1)
    expect(failures.first["actor"]).to eq("bob")
  end

  it "supports #count with a block" do
    expect(sink.count { |r| r["operation"] == "composite_sign" }).to eq(2)
  end

  it "supports #find" do
    carol = sink.find { |r| r["actor"] == "carol" }
    expect(carol["operation"]).to eq("tc_sign")
  end

  it "supports #group_by" do
    grouped = sink.group_by { |r| r["operation"] }
    expect(grouped["composite_sign"].length).to eq(2)
    expect(grouped["cms_verify"].length).to eq(1)
  end

  it "supports #map" do
    actors = sink.map { |r| r["actor"] }.sort
    expect(actors).to eq(%w[alice alice bob carol])
  end

  it "supports #include? via #==" do
    expect(sink.to_a.length).to eq(4)
    expect(sink.to_a.first["actor"]).to eq("alice")
  end

  it "is empty when no records have been written" do
    empty_sink = Confium::Audit::MemorySink.new
    expect(empty_sink.to_a).to eq([])
    expect(empty_sink.count).to eq(0)
  end
end
