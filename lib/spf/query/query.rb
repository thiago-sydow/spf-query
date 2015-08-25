require 'resolv'
require 'resolv/dns/resource/in/spf'
require 'byebug'
module SPF
  module Query
    #
    # Queries the domain for it's SPF record.
    #
    # @param [String] domain
    #   The domain to query.
    #
    # @param [Resolv::DNS] resolver
    #   The optional resolver to use.
    #
    # @param [Integer] max_lookups
    #   Max inner lookups to search.
    #
    # @return [String, nil]
    #   The SPF record or `nil` if there is none.
    #
    # @api semipublic
    #
    def self.query(domain,resolver=Resolv::DNS.new, max_lookups=1)
      # check for an SPF record on the domain
      begin
        record = resolver.getresource(domain, Resolv::DNS::Resource::IN::SPF)

        return record.strings.join
      rescue Resolv::ResolvError
      end

      query_result = process_domains(["_spf.#{domain}", domain], resolver)
      return nil if query_result[:text].empty?

      return_text = query_result[:text]
      additional_domains = query_result[:included]

      if additional_domains
        i = 1
        while i < max_lookups
          additional_result = process_domains(additional_domains, resolver)
          break unless additional_result
          return_text << additional_result[:text]
          additional_domains = additional_result[:included]
          i += 1
        end
      end

      return return_text.split(' ').uniq.join(' ')
    end

    def self.process_domains(domains, resolver)
      result_hash = { text: '', included: [] }

      domains.each do |host|
        begin
          records = resolver.getresources(host, Resolv::DNS::Resource::IN::TXT)

          records.each do |record|
            txt = record.strings.join

            if txt.include?('v=spf1')
              domains = txt.scan(/include:([^\s]+)/)
              result_hash[:text] << " #{txt}"
              result_hash[:included] += domains.flatten.compact.uniq
            end
          end
        rescue Resolv::ResolvError
        end
      end

      return result_hash
    end

  end
end
