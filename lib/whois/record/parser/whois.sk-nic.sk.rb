#--

require 'whois/record/parser/base'
require 'whois/record/scanners/whois.sk-nic.sk.rb'

module Whois
  class Record
    class Parser

      class WhoisSkNicSk < Base
        include Scanners::Scannable

        self.scanner = Scanners::WhoisSkNicSk

        property_supported :domain do
          node("Domain") { |str| str.downcase }
        end

        property_not_supported :domain_id

        property_supported :status do
          if content_for_scanner =~ /^EPP Status:\s+(.+)\n/
            statuses = $1.downcase.split(",").collect { |s| s.strip }
            if statuses.include?("ok")
              return :registered
            elsif statuses.include?("redemptionperiod")
              return :expired
            elsif statuses.include?("clientupdateprohibited")
              return :registered
            elsif statuses.include?("clienttransferprohibited")
              return :registered
            elsif statuses.include?("inactive")
              return :registered
            else
              Whois.bug!(ParserError, "Unknown status `#{$1}'.")
            end
          else
            return :available
          end
        end

        property_supported :available? do
          !!node("status:available")
        end

        property_supported :registered? do
          !available?
        end

        property_supported :created_on do
          node("Created") { |str| Time.parse(str) }
        end

        property_supported :updated_on do
          node("Updated") { |str| Time.parse(str) }
        end

        property_supported :expires_on do
          node("Valid Until") { |str| Time.parse(str) }
        end

        property_supported :nameservers do
          if not node?("Nameserver")
            return []
          else
            node("Nameserver").map do |line|
              if line =~ /(.+) \((.+)\)/
                name = $1
                ipv4, ipv6 = $2.split(', ')
                Record::Nameserver.new(:name => name, :ipv4 => ipv4, :ipv6 => ipv6)
              else
                Record::Nameserver.new(:name => line.strip)
              end
            end
          end
        end

        property_supported :registrar do
          build_contact(node("Registrar"), Whois::Record::Contact::TYPE_REGISTRAR)
        end

        property_supported :registrant_contacts do
          build_contact(node("Registrant"), Whois::Record::Contact::TYPE_REGISTRANT)
        end

        property_supported :admin_contacts do
          build_contact(node("Admin Contact"), Whois::Record::Contact::TYPE_ADMINISTRATIVE)
        end

        property_supported :technical_contacts do
          build_contact(node("Tech Contact"), Whois::Record::Contact::TYPE_TECHNICAL)
        end

        def response_throttled?
          !!node("response:throttled")
        end
        private

        def build_contact(element, type)
          node("Contact-#{element}") do |hash|
            Record::Contact.new(
              :id           => hash["Contact"] || hash["Registrar"],
              :type         => type,
              :name         => hash["Name"],
              :organization => hash["Organization"],
              :email        => hash["Email"],
              :phone        => hash["Phone"],
              :address      => hash["Street"],
              :city         => hash["City"],
              :zip          => hash["Postal Code"],
              :country_code => hash["Country Code"],
              :created_on   => hash["Created"] ? Time.parse(hash["Created"]) : nil,
              :updated_on   => (hash["Updated"] && hash["Updated"] != "0000-00-00") ? Time.parse(hash["Updated"]) : nil
            )
          end
        end


      end

    end
  end
end
