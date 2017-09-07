# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.uk/uk/property_nameservers_with_ip.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.uk.rb'

describe Whois::Record::Parser::WhoisNicUk, "property_nameservers_with_ip.expected" do

  subject do
    file = fixture("responses", "whois.nic.uk/uk/property_nameservers_with_ip.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(2)
      expect(subject.nameservers[0]).to be_a(Whois::Record::Nameserver)
      expect(subject.nameservers[0].name).to eq("ns0.netbenefit.co.uk")
      expect(subject.nameservers[0].ipv4).to eq("212.53.64.30")
      expect(subject.nameservers[1]).to be_a(Whois::Record::Nameserver)
      expect(subject.nameservers[1].name).to eq("ns1.netbenefit.co.uk")
      expect(subject.nameservers[1].ipv4).to eq("212.53.77.30")
    end
  end
end
