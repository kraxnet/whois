# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.register.bg/bg/property_nameservers_with_ip.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.register.bg.rb'

describe Whois::Record::Parser::WhoisRegisterBg, "property_nameservers_with_ip.expected" do

  subject do
    file = fixture("responses", "whois.register.bg/bg/property_nameservers_with_ip.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(2)
      expect(subject.nameservers[0]).to be_a(Whois::Record::Nameserver)
      expect(subject.nameservers[0].name).to eq("chicken.orbitel.bg")
      expect(subject.nameservers[0].ipv4).to eq("195.24.32.5")
      expect(subject.nameservers[1]).to be_a(Whois::Record::Nameserver)
      expect(subject.nameservers[1].name).to eq("ns.orbitel.bg")
      expect(subject.nameservers[1].ipv4).to eq("195.24.32.2")
    end
  end
end
