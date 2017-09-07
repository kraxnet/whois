# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.srs.net.nz/nz/status_invalid.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.srs.net.nz.rb'

describe Whois::Record::Parser::WhoisSrsNetNz, "status_invalid.expected" do

  subject do
    file = fixture("responses", "whois.srs.net.nz/nz/status_invalid.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#status" do
    it do
      expect(subject.status).to eq(:invalid)
    end
  end
  describe "#available?" do
    it do
      expect(subject.available?).to eq(false)
    end
  end
  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(false)
    end
  end
  describe "#created_on" do
    it do
      expect(subject.created_on).to eq(nil)
    end
  end
  describe "#updated_on" do
    it do
      expect(subject.updated_on).to eq(nil)
    end
  end
  describe "#expires_on" do
    it do
      expect(subject.expires_on).to eq(nil)
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers).to eq([])
    end
  end
  describe "#valid?" do
    it do
      expect(subject.valid?).to eq(false)
    end
  end
  describe "#invalid?" do
    it do
      expect(subject.invalid?).to eq(true)
    end
  end
  describe "#response_throttled?" do
    it do
      expect(subject.response_throttled?).to eq(false)
    end
  end
end
