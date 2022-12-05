# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "openssl"

# This filter allow you to generate predictable, string encoded hashed keys 
# based om event contents and timestamp. This can be used to avoid getting 
# duplicate records indexed into Elasticsearch.
#
# Hashed keys to be generated based on full or partial hashes and
# has the ability to prefix these keys based on the event timestamp in order
# to make then largely ordered by timestamp, which tend to lead to increased
# indexing performance for event based use cases where data is being indexed
# in near real time.
#
# When used with the timestamp prefix enabled, it should ideally be run after 
# the date filter has run and populated the @timestamp field.
class LogStash::Filters::Hashid < LogStash::Filters::Base
  config_name "hashid"

  # Source field(s) to base the hash calculation on
  config :source, :validate => :array, :default => ['message']

  # Target field.
  # Will overwrite current value of a field if it exists.
  config :target, :validate => :string, :default => 'hashid'

  # Encryption key to be used when generating cryptographic hashes
  config :key, :validate => :password, :default => 'hashid'

  # Hash function to use
  config :method, :validate => ['SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5'], :default => 'MD5'

  # If full hash generated is not to be used, this parameter specifies how many bytes that should be used
  # If not specified, the full hash will be used
  config :hash_bytes_used, :validate => :number

  # Use the timestamp to generate an ID prefix
  config :add_timestamp_prefix, :validate => :boolean, :default => true

  CHARS = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'.chars.to_a.freeze
  SHIFTS = [18, 12, 6, 0].freeze

  def register
    # convert to symbol for faster comparisons
    @method = @method.to_sym
    @digest = select_digest(@method)
  end

  def filter(event)
    hmac = OpenSSL::HMAC.new(@key.value, @digest.new)

    @source.sort.each do |k|
      hmac.update("|#{k}|#{event.get(k)}") 
    end

    hash = hmac.digest

    if !@hash_bytes_used.nil? && @hash_bytes_used > 0 && hash.length > @hash_bytes_used
      hash = hash[(-1 * @hash_bytes_used), @hash_bytes_used]
    end

    epoch_array = []
    if @add_timestamp_prefix
      epoch = event.get('@timestamp').to_i
      epoch_array.push(epoch >> 24)
      epoch_array.push((epoch >> 16) % 256)
      epoch_array.push((epoch >> 8) % 256)
      epoch_array.push(epoch % 256)
    end

    binary_array = epoch_array + hash.unpack('C*')

    event.set(@target, encode_to_sortable_string(binary_array).force_encoding(Encoding::UTF_8))
  end

  def select_digest(method)
    case method
    when :SHA1
      OpenSSL::Digest::SHA1
    when :SHA256
      OpenSSL::Digest::SHA256
    when :SHA384
      OpenSSL::Digest::SHA384
    when :SHA512
      OpenSSL::Digest::SHA512
    when :MD5
      OpenSSL::Digest::MD5
    else
      # we really should never get here
      raise(LogStash::ConfigurationError, "Unknown digest for method=#{method.to_s}")
    end
  end

  def encode_to_sortable_string(data)
    idxes = []
    to_take = 0
    data.each_slice(3) do |part0, part1, part2|
      to_take = 0
      if part1.nil?
        part1 = part2 = 0
        to_take = 2
      end
      if part2.nil?
        part2 = 0
        to_take = 1
      end
      group24 = (part0 << 16) | (part1 << 8) | part2
      idxes.concat(SHIFTS.map{|n| (group24 >> n) & 0x3f })
    end
    CHARS.values_at(*idxes.take(idxes.size - to_take)).join
  end
end
