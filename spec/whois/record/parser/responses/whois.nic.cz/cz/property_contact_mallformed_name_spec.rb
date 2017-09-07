# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.cz/cz/property_contact_mallformed_name.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.cz.rb'

describe Whois::Record::Parser::WhoisNicCz, "property_contact_mallformed_name.expected" do

  subject do
    file = fixture("responses", "whois.nic.cz/cz/property_contact_mallformed_name.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts[0].name).to eq("Hynek Hluchý logo Hynek Hynek Hluchý logo Hluchý")
    end
  end
end
