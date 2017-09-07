# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.registry.net.za/za/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.registry.net.za.rb'

describe Whois::Record::Parser::WhoisRegistryNetZa, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.registry.net.za/za/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#disclaimer" do
    it do
      expect(subject.disclaimer).to eq("The use of this Whois facility is subject to the following terms and\nconditions. https://registry.net.za/whois_terms\nCopyright (c) UniForum SA 1995-2014\n")
    end
  end
  describe "#domain" do
    it do
      expect(subject.domain).to eq("google.co.za")
    end
  end
  describe "#domain_id" do
    it do
      expect { subject.domain_id }.to raise_error Whois::AttributeNotSupported
    end
  end
  describe "#status" do
    it do
      expect(subject.status).to eq(:registered)
    end
  end
  describe "#available?" do
    it do
      expect(subject.available?).to eq(false)
    end
  end
  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(true)
    end
  end
  describe "#created_on" do
    it do
      expect(subject.created_on).to eq(Time.parse("2001-06-25"))
    end
  end
  describe "#updated_on" do
    it do
      expect { subject.updated_on }.to raise_error Whois::AttributeNotSupported
    end
  end
  describe "#expires_on" do
    it do
      expect(subject.expires_on).to eq(Time.parse("2014-06-25"))
    end
  end
  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Record::Registrar)
      expect(subject.registrar.id).to eq(nil)
      expect(subject.registrar.name).to eq("MarkMonitor")
      expect(subject.registrar.organization).to eq(nil)
      expect(subject.registrar.url).to eq(nil)
    end
  end
  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Record::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Record::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].name).to eq("Google Inc.")
      expect(subject.registrant_contacts[0].organization).to eq(nil)
      expect(subject.registrant_contacts[0].address).to eq("1600 Amphitheatre Parkway\nMountain View\nCA\nUS\n94043")
      expect(subject.registrant_contacts[0].city).to eq(nil)
      expect(subject.registrant_contacts[0].zip).to eq(nil)
      expect(subject.registrant_contacts[0].state).to eq(nil)
      expect(subject.registrant_contacts[0].country_code).to eq(nil)
      expect(subject.registrant_contacts[0].phone).to eq("+1.6502530000")
      expect(subject.registrant_contacts[0].fax).to eq("+1.6506188571")
      expect(subject.registrant_contacts[0].email).to eq("dns-admin@google.com")
      expect(subject.registrant_contacts[0].created_on).to eq(nil)
      expect(subject.registrant_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#admin_contacts" do
    it do
      expect { subject.admin_contacts }.to raise_error Whois::AttributeNotSupported
    end
  end
  describe "#technical_contacts" do
    it do
      expect { subject.technical_contacts }.to raise_error Whois::AttributeNotSupported
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(4)
      expect(subject.nameservers[0]).to be_a(Whois::Record::Nameserver)
      expect(subject.nameservers[0].name).to eq("ns1.google.com")
      expect(subject.nameservers[0].ipv4).to eq(nil)
      expect(subject.nameservers[0].ipv6).to eq(nil)
      expect(subject.nameservers[1]).to be_a(Whois::Record::Nameserver)
      expect(subject.nameservers[1].name).to eq("ns2.google.com")
      expect(subject.nameservers[1].ipv4).to eq(nil)
      expect(subject.nameservers[1].ipv6).to eq(nil)
      expect(subject.nameservers[2]).to be_a(Whois::Record::Nameserver)
      expect(subject.nameservers[2].name).to eq("ns3.google.com")
      expect(subject.nameservers[2].ipv4).to eq(nil)
      expect(subject.nameservers[2].ipv6).to eq(nil)
      expect(subject.nameservers[3]).to be_a(Whois::Record::Nameserver)
      expect(subject.nameservers[3].name).to eq("ns4.google.com")
      expect(subject.nameservers[3].ipv4).to eq(nil)
      expect(subject.nameservers[3].ipv6).to eq(nil)
    end
  end
end
