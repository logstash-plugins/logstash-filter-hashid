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

  # Timestamp field to use for the timestamp prefix
  config :timestamp_field, :validate => :string, :default => '@timestamp'

  # Target field.
  # Will overwrite current value of a field if it exists.
  config :target, :validate => :string, :default => 'hashid'

  # Encryption key to be used when generating cryptographic hashes
  config :key, :validate => :string, :default => 'hashid'

  # Hash function to use
  config :method, :validate => ['SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5'], :default => 'MD5'

  # If full hash generated is not to be used, this parameter specifies how many bytes that should be used
  # If not specified, the full hash will be used
  config :hash_bytes_used, :validate => :number

  # Use the timestamp to generate an ID prefix
  config :timestamp_prefix, :validate => :boolean, :default => true

  def register
    # convert to symbol for faster comparisons
    @method = @method.to_sym
    @digest = select_digest(@method)
  end

  def filter(event)
    data = ""
        
    @source.sort.each do |k|
      data << "|#{k}|#{event[k]}"
    end

    hash = OpenSSL::HMAC.digest(@digest, @key, data)

    if !@hash_bytes_used.nil? && @hash_bytes_used > 0 && hash.length > @hash_bytes_used
      hash = hash[(-1 * @hash_bytes_used), @hash_bytes_used]
    end

    epoch_array = []
    if @timestamp_prefix
      epoch = event[@timestamp_field].to_i
      epoch_array = []
      epoch_array.push(epoch >> 24)
      epoch_array.push((epoch >> 16) % 256)
      epoch_array.push((epoch >> 8) % 256)
      epoch_array.push(epoch % 256)
    end

    binary_array = epoch_array + hash.unpack('C*')

    event[@target] = encode_to_sortable_string(binary_array).force_encoding(Encoding::UTF_8)
  end

  def select_digest(method)
    case method
    when :SHA1
      OpenSSL::Digest::SHA1.new
    when :SHA256
      OpenSSL::Digest::SHA256.new
    when :SHA384
      OpenSSL::Digest::SHA384.new
    when :SHA512
      OpenSSL::Digest::SHA512.new
    when :MD5
      OpenSSL::Digest::MD5.new
    else
      # we really should never get here
      raise(LogStash::ConfigurationError, "Unknown digest for method=#{method.to_s}")
    end
  end

  def encode_to_sortable_string(data)
    chars = '-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'
    encoded_string = ""
    offset = 0
    while offset < data.length do
      buf = data[offset,3]
      offset+=3

      pad = '' # padding for this group of 4 characters
      while buf.length < 3
        buf.push(0)
        pad << '='
      end

      group24 = (buf[0] << 16) | (buf[1] << 8) | buf[2] # current 3 bytes as a 24 bit value
      encoded = chars[(group24 >> 18) & 0x3f, 1] # read the 24 bit value 6 bits at a time
      encoded << chars[(group24 >> 12) & 0x3f, 1]
      encoded << chars[(group24 >> 6) & 0x3f, 1]
      encoded << chars[(group24 >> 0) & 0x3f, 1]
      encoded[4 - pad.length, pad.length] = pad # add the padding
      encoded_string << encoded
    end

    encoded_string.tr('=','')
  end
end
