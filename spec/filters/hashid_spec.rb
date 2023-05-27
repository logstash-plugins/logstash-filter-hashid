# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/filters/hashid"

describe LogStash::Filters::Hashid do

  let(:plugin) { described_class.new(config) }

  describe 'Full MD5, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'MD5'
          add_timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'Fpbg8CbSbOQ81JSd3HmPFk'
    end
  end

  describe '12 byte MD5, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'MD5'
          add_timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'qSqS_gZ8GqZGA8d2'
    end
  end

  describe 'Full SHA1, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA1'
          add_timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'sOoRSauukymQT3a8q4C8FZyDncw'
    end
  end

  describe '12 byte SHA1, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA1'
          add_timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'arW8XSWIHJ8EYguE'
    end
  end

  describe 'Full SHA256, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA256'
          add_timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'UZ8NNsx-LsLjV7S6ElKKyMG_Xv274XQE_-nRv-UNgm3'
    end
  end

  describe '12 byte SHA256, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA256'
          add_timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'm0NantFBrDk6qABW'
    end
  end

  describe 'Full SHA384, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA384'
          add_timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'uvdBF5FfTA-ns_Ou6QWTTKsmOCH8T7j6691tr3N7DtZlAeDSvawhWfTAKwwJq9c2'
    end
  end

  describe '12 byte SHA384, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA384'
          add_timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'vawhWfTAKwwJq9c2'
    end
  end

  describe 'Full SHA512, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA512'
          add_timestamp_prefix => false
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == 'ODUuPJaePwJupNWp1exdZJWRrz1aLATtrD0yzOrVBce9hUkhtW266C4djjkp4kqLVU9LtlPh0IermOgJpJx9VV'
    end
  end

  describe '12 byte SHA512, no timestamp prefix' do
    config <<-CONFIG
      filter {
        hashid {
          source => ['message']
          method => 'SHA512'
          add_timestamp_prefix => false
          hash_bytes_used => 12
        }
      }
    CONFIG

    sample("message" => "testmessage") do
      insist { subject.get("hashid") } == '4eo4DfU8alIKIoe1'
    end
  end

  context 'Timestamps' do
    epoch_time = Time.at(1451613600).gmtime

    describe 'Full MD5 with timestamp prefix' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['message']
            method => 'MD5'
            add_timestamp_prefix => true
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "message" => "testmessage") do
        insist { subject.get("hashid") } == 'KcMSc3COv1IOrOqLmF_6PG3gaZB'
      end
    end

    describe 'Full MD5 with timestamp prefix and concatenated source part 1' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['part1','part2']
            method => 'MD5'
            add_timestamp_prefix => true
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "part1" => "test", "part2" => "message") do
        insist { subject.get("hashid") } == 'KcMSc-8mTz750RP7I-pCuae4U6o'
      end
    end

    describe 'Full MD5 with timestamp prefix and concatenated source part 2' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['part2','part1']
            method => 'MD5'
            add_timestamp_prefix => true
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "part2" => "message", "part1" => "test") do
        insist { subject.get("hashid") } == 'KcMSc-8mTz750RP7I-pCuae4U6o'
      end
    end

    describe 'Full MD5 with timestamp prefix and concatenated timestamp' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['@timestamp','message']
            method => 'MD5'
            add_timestamp_prefix => true
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "message" => "testmessage") do
        insist { subject.get("hashid") } == 'KcMSc6IRDIqJMU6VN1x0TKt2fIo'
      end
    end

    describe '12 byte MD5 with timestamp prefix' do
      config <<-CONFIG
        filter {
          hashid {
            source => ['message']
            method => 'MD5'
            add_timestamp_prefix => true
            hash_bytes_used => 12
          }
        }
      CONFIG

      sample("@timestamp" => epoch_time, "message" => "testmessage") do
        insist { subject.get("hashid") } == 'KcMScCbSbOQ81JSd3HmPFk'
      end
    end

  end

  describe "debugging key" do
    let(:config) {{ "key" => "$ecre&-key" }}

    it "should not show origin value" do
      expect(plugin.logger).to receive(:debug).with('<password>')

      plugin.register
      plugin.logger.send(:debug, plugin.key.to_s)
    end
  end
end
