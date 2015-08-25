require 'spec_helper'
require 'spf/query/query'

describe SPF::Query do
  subject { described_class }

  describe ".query" do
    let(:domain) { 'gmail.com' }

    it "should return the first SPF record" do
      expect(subject.query(domain)).to be == %{v=spf1 redirect=_spf.google.com}
    end

    context "when _spf.domain.com exists" do
      let(:domain) { 'google.com' }

      it "should return _spf.domain and domain.com results" do
        expect(subject.query(domain)).to be == %{v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all include:_spf.google.com}
      end
    end

    context "when the domain has a SPF type record" do
      let(:domain) { 'getlua.com' }

      it "should prefer the SPF type record over other TXT records" do
        expect(subject.query(domain)).to be == %{v=spf1 include:_spf.google.com include:mail.zendesk.com include:servers.mcsv.net -all}
      end
    end

    context "when given an invalid domain" do
      let(:domain) { 'foo.bar.com' }

      it "should return nil" do
        expect(subject.query(domain)).to be_nil
      end
    end

    context "when max_lookups is greater than 1" do
      let(:domain) { 'google.com' }

      subject { SPF::Query.query(domain, Resolv::DNS.new, 2) }

      it "should return recursively by the value set" do
        expected_result = %w{v=spf1 include:_netblocks.google.com include:_netblocks2.google.com
          include:_netblocks3.google.com ~all include:_spf.google.com ip4:64.18.0.0/20 ip4:64.233.160.0/19 ip4:66.102.0.0/20
          ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 ip4:173.194.0.0/16 ip4:207.126.144.0/20 ip4:209.85.128.0/17
          ip4:216.58.192.0/19 ip4:216.239.32.0/19 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36
          ip6:2800:3f0:4000::/36 ip6:2a00:1450:4000::/36 ip6:2c0f:fb50:4000::/36}

        is_expected.to be == expected_result.join(' ')
      end
    end
  end
end
