#--

require 'whois/record/scanners/base'

module Whois
  class Record
    module Scanners

      class WhoisSkNicSk < Base

        @throttled

        self.tokenizers += [
            :skip_comment,
            :skip_empty_line,
            :scan_response_throttled,
            :scan_available,
            :scan_section,
        ]

        tokenizer :skip_comment do
          @input.skip(/^%.*\n/)
        end

        tokenizer :scan_section do
          if @input.match?(/^(Domain|Registrar|Contact):\s+(.+?)\n/)
            @tmp["_section"] = "#{@input[1]}"
            while scan_keyvalue
            end
            @tmp.delete("_section")
          end
        end

        tokenizer :scan_keyvalue do
          if @input.scan(/(.+?):(.*?)(\n|\z)/)
            key, value = @input[1].strip, @input[2].strip
            if @tmp['_section'] == "Domain"
              target = @ast
            elsif ["Registrar","Contact"].include?(@tmp['_section'])
              if ["Registrar","Contact"].include?(key)
                @tmp['_section'] = "Contact-#{value}"
              end
              target = @ast[@tmp['_section']] ||= {}
            else
              target = @ast[@tmp['_section']] ||= {}
            end

            if target[key].nil?
              target[key] = value
            else
              target[key] = Array.wrap(target[key])
              target[key] << value
            end
          end
        end

        tokenizer :scan_available do
          if @input.scan(/^Domain not found\./)
            @ast["status:available"] = true
            @ast["status"] = "No entries found"
          end
        end

        tokenizer :scan_response_throttled do
          if @input.exist?(/^Query rate of .+ queries .+ exceeded/)
            @ast["response:throttled"] = true
            @input.skip(/^.+\n/)
          end
        end

      end
    end
  end
end
