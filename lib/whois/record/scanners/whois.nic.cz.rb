#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2015 Simone Carletti <weppos@weppos.net>
#++


require 'whois/record/scanners/base'

module Whois
  class Record
    module Scanners

      # Scanner for the whois.nic.cz server.
      class WhoisNicCz < Base

        self.tokenizers += [
            :scan_disclaimer,
            :skip_whois_server_version,
            :skip_timestamp,
            :skip_empty_line,
            :scan_available,
            :scan_to_be_deleted,
            :skip_empty_comment,
            :skip_secondardy_available,
            :scan_sections,
            :scan_response_throttled,
        ]

        tokenizer :scan_disclaimer do
          if @input.match?(/^%  \(c\) .+ CZ.NIC, z.s.p.o./)
            lines = @input.scan_until(/% \n% \n/)
            lines = lines.split("\n").collect{|s| s.gsub(/^% /,'')}
            @ast["field:disclaimer"] = lines.join("\n")
          end
        end

        tokenizer :skip_whois_server_version do
          @input.skip(/^% Whoisd Server Version: (.+)\n/)
        end

        tokenizer :skip_timestamp do
          @input.skip(/^% Timestamp: (.+)\n/)
        end

        tokenizer :scan_available do
          if @input.scan(/^%ERROR:101: no entries found\n/)
            @ast["status:available"] = true
            @ast["status"] = "No entries found"
          end
        end

        tokenizer :scan_to_be_deleted do
          if @input.scan(/^domain: .+?\nstatus:\s+?To be deleted\n/)
            @ast["status"] = "To be deleted"
          end
        end

        tokenizer :skip_empty_comment do
          @input.skip(/^% \n/)
        end

        tokenizer :skip_secondardy_available do
          @input.skip(/% No entries found.\n/)
        end

        tokenizer :scan_response_throttled do
          if @input.match?(/Your connection limit exceeded\. Please slow down and try again later/)
            @ast["response:throttled"] = true
            @input.skip(/^.+\n/)
          end
        end

        tokenizer :scan_sections do
          if @input.match?(/^(domain|contact|nsset|keyset):\s+(.+?)\n/)
            section = @input[1]
            handle = @input[2]
            @content = {}
            while @input.match?(/\A[a-z].+?: .*?\n/) && @input.scan(/\A([a-z].+?): (.*?)\n/)
              key, value = @input[1].strip, @input[2].strip
              if (key == 'address' || key == 'name') &&
                while @input.match?(/\A([[[:upper:]][[:lower:]][[:digit:]][[:space:]]]*?)\n/) && @input.scan(/\A([[[:upper:]][[:lower:]][[:digit:]][[:space:]]]*?)\n/)
                  value = [value, @input[1]].join(" ")
                end
              end
              if @content[key].nil?
                @content[key] = value
              else
                @content[key] = Array.wrap(@content[key])
                @content[key] << value
              end
              break if @input.skip(/^\n/)
            end
            if section=="domain"
              @ast.merge!(@content)
            else
              @ast["#{section}-#{handle}"]=@content
            end
          end
        end

      end
    end
  end
end
