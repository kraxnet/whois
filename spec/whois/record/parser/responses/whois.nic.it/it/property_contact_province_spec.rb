# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.it/it/property_contact_province.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.it.rb'

describe Whois::Record::Parser::WhoisNicIt, "property_contact_province.expected" do

  subject do
    file = fixture("responses", "whois.nic.it/it/property_contact_province.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Record::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Record::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].id).to eq("HTML1-ITNIC")
      expect(subject.registrant_contacts[0].name).to eq("HTML.it srl")
      expect(subject.registrant_contacts[0].organization).to eq("HTML.it srl")
      expect(subject.registrant_contacts[0].address).to eq("Viale Alessandrino, 595")
      expect(subject.registrant_contacts[0].city).to eq("Roma")
      expect(subject.registrant_contacts[0].zip).to eq("00172")
      expect(subject.registrant_contacts[0].state).to eq("RM")
      expect(subject.registrant_contacts[0].country_code).to eq("IT")
      expect(subject.registrant_contacts[0].created_on).to eq(Time.parse("2007-03-01 10:28:08"))
      expect(subject.registrant_contacts[0].updated_on).to eq(Time.parse("2007-03-01 10:28:08"))
    end
  end
end
