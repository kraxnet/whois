# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.cz/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/record/parser/whois.nic.cz.rb'

describe Whois::Record::Parser::WhoisNicCz, "status_registered.expected" do

  before(:each) do
    file = fixture("responses", "whois.nic.cz/status_registered.txt")
    part = Whois::Record::Part.new(:body => File.read(file))
    @parser = klass.new(part)
  end

  describe "#disclaimer" do
    it do
      @parser.disclaimer.should == " (c) 2006-2010 CZ.NIC, z.s.p.o.\n\nIntended use of supplied data and information\n\nData contained in the domain name register, as well as information\nsupplied through public information services of CZ.NIC association,\nare appointed only for purposes connected with Internet network\nadministration and operation, or for the purpose of legal or other\nsimilar proceedings, in process as regards a matter connected\nparticularly with holding and using a concrete domain name.\n\nFull text available at:\nhttp://www.nic.cz/page/306/intended-use-of-supplied-data-and-information/\n\nSee also a search service at http://www.nic.cz/whois/\n\n"
    end
  end
  describe "#domain" do
    it do
      @parser.domain.should == "google.cz"
    end
  end
  describe "#domain_id" do
    it do
      lambda { @parser.domain_id }.should raise_error(Whois::PropertyNotSupported)
    end
  end
  describe "#referral_url" do
    it do
      lambda { @parser.referral_url }.should raise_error(Whois::PropertyNotSupported)
    end
  end
  describe "#referral_whois" do
    it do
      lambda { @parser.referral_whois }.should raise_error(Whois::PropertyNotSupported)
    end
  end
  describe "#status" do
    it do
      @parser.status.should be_a(Array)
      @parser.status.should == [:registered]
    end
  end
  describe "#available?" do
    it do
      @parser.available?.should == false
    end
  end
  describe "#registered?" do
    it do
      @parser.registered?.should == true
    end
  end
  describe "#created_on" do
    it do
      @parser.created_on.should be_a(Time)
      @parser.created_on.should == Time.parse("2000-07-21 15:21:00")
    end
  end
  describe "#updated_on" do
    it do
      @parser.updated_on.should be_a(Time)
      @parser.updated_on.should == Time.parse("2006-08-31 14:35:00")
    end
  end
  describe "#expires_on" do
    it do
      @parser.expires_on.should be_a(Time)
      @parser.expires_on.should == Time.parse("2013-07-22")
    end
  end
  describe "#registrar" do
    it do
      @parser.registrar.should be_a(Whois::Record::Registrar)
      @parser.registrar.id.should           == "REG-ACTIVE24"
      @parser.registrar.name.should         == "REG-ACTIVE24"
    end
  end
  describe "#registrant_contacts" do
    it do
      @parser.registrant_contacts.should be_a(Array)
      @parser.registrant_contacts.should have(1).items
      @parser.registrant_contacts[0].should be_a(Whois::Record::Contact)
      @parser.registrant_contacts[0].type.should          == Whois::Record::Contact::TYPE_REGISTRANT
      @parser.registrant_contacts[0].id.should            == "SB:ACTIVE24-SGOO406652"
      @parser.registrant_contacts[0].name.should          == "Google Inc."
      @parser.registrant_contacts[0].organization.should  == "Google Inc."
      @parser.registrant_contacts[0].address.should       == "1600 Ampitheatre Parkway\nMountain View CA\n94043\nUS"
      @parser.registrant_contacts[0].city.should          == nil
      @parser.registrant_contacts[0].zip.should           == nil
      @parser.registrant_contacts[0].state.should         == nil
      @parser.registrant_contacts[0].country_code.should  == nil
      @parser.registrant_contacts[0].email.should         == "dns-admin@google.com"
      @parser.registrant_contacts[0].created_on.should    == Time.parse("2006-07-31 19:25:00")
      @parser.registrant_contacts[0].updated_on.should    == nil
    end
  end
  describe "#admin_contacts" do
    it do
      @parser.admin_contacts.should be_a(Array)
      @parser.admin_contacts.should have(1).items
      @parser.admin_contacts[0].should be_a(Whois::Record::Contact)
      @parser.admin_contacts[0].type.should          == Whois::Record::Contact::TYPE_ADMIN
      @parser.admin_contacts[0].id.should            == "ACTIVE24-PBFF025571"
      @parser.admin_contacts[0].name.should          == "Diana Ly"
      @parser.admin_contacts[0].organization.should  == nil
      @parser.admin_contacts[0].address.should       == "1600 Ampitheatre Parkway\nMountain View CA\n94043\nUS"
      @parser.admin_contacts[0].city.should          == nil
      @parser.admin_contacts[0].zip.should           == nil
      @parser.admin_contacts[0].state.should         == nil
      @parser.admin_contacts[0].country_code.should  == nil
      @parser.admin_contacts[0].phone.should         == "+16.503300100"
      @parser.admin_contacts[0].fax.should           == "+16.506188571"
      @parser.admin_contacts[0].email.should         == "dns-admin@google.com"
      @parser.admin_contacts[0].created_on.should    == Time.parse("2006-07-31 19:15:00")
      @parser.admin_contacts[0].updated_on.should    == nil
    end
  end
  describe "#technical_contacts" do
    it do
      @parser.technical_contacts.should be_a(Array)
      @parser.technical_contacts.should have(2).items
      @parser.technical_contacts[0].id.should            == "SB:MARKMONITOR"
      @parser.technical_contacts[0].name.should          == "eMarkmonitor Inc. dba Markmonitor"
      @parser.technical_contacts[1].should be_a(Whois::Record::Contact)
      @parser.technical_contacts[1].type.should          == Whois::Record::Contact::TYPE_TECHNICAL
      @parser.technical_contacts[1].id.should            == "CCOPS"
      @parser.technical_contacts[1].name.should          == "Domain Administrator"
      @parser.technical_contacts[1].organization.should  == nil
      @parser.technical_contacts[1].address.should       == "10400 Overland Rd PMB 155\nBoise ID\n83709\nUS"
      @parser.technical_contacts[1].city.should          == nil
      @parser.technical_contacts[1].zip.should           == nil
      @parser.technical_contacts[1].state.should         == nil
      @parser.technical_contacts[1].country_code.should  == nil
      @parser.technical_contacts[1].phone.should         == "+12.083895740"
      @parser.technical_contacts[1].fax.should           == "+12.083895799"
      @parser.technical_contacts[1].email.should         == "ccops@markmonitor.com"
      @parser.technical_contacts[1].created_on.should    == Time.parse("2007-05-08 01:25:00")
      @parser.technical_contacts[1].updated_on.should    == nil
    end
  end
  describe "#nameservers" do
    it do
      @parser.nameservers.should be_a(Array)
      @parser.nameservers.should have(4).items
      @parser.nameservers[0].should be_a(Whois::Record::Nameserver)
      @parser.nameservers[0].name.should == "ns3.google.com"
      @parser.nameservers[1].should be_a(Whois::Record::Nameserver)
      @parser.nameservers[1].name.should == "ns4.google.com"
      @parser.nameservers[2].should be_a(Whois::Record::Nameserver)
      @parser.nameservers[2].name.should == "ns1.google.com"
      @parser.nameservers[3].should be_a(Whois::Record::Nameserver)
      @parser.nameservers[3].name.should == "ns2.google.com"
    end
  end
end
