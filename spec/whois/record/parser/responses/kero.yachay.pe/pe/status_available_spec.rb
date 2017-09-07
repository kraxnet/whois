# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/kero.yachay.pe/pe/status_available.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/kero.yachay.pe.rb'

describe Whois::Record::Parser::KeroYachayPe, "status_available.expected" do

  subject do
    file = fixture("responses", "kero.yachay.pe/pe/status_available.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#status" do
    it do
      expect(subject.status).to eq(:available)
    end
  end
  describe "#available?" do
    it do
      expect(subject.available?).to eq(true)
    end
  end
  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(false)
    end
  end
  describe "#created_on" do
    it do
      expect { subject.created_on }.to raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#updated_on" do
    it do
      expect { subject.updated_on }.to raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#expires_on" do
    it do
      expect { subject.expires_on }.to raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers).to eq([])
    end
  end
  describe "#response_throttled?" do
    it do
      expect(subject.response_throttled?).to eq(false)
    end
  end
end
