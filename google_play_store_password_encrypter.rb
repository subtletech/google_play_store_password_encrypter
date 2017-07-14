require 'openssl'
require 'base64'

module GooglePlayStorePasswordEncrypter
  GOOGLE_DEFAULT_PUBLIC_KEY = 'AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ=='.freeze

  def self.encrypt(login, password)
    combined = login + "\x00" + password
    encrypted = p_key.public_encrypt(combined, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
    encode64(key_signature + encrypted)
  end

  def self.binary_key
    @binary_key ||= Base64.decode64(GOOGLE_DEFAULT_PUBLIC_KEY)
  end

  def self.key_signature
    @key_signature ||= "\x00" << Digest::SHA1.digest(binary_key)[0, 4]
  end

  def self.p_key
    return @p_key if defined? @p_key

    i = read_int(binary_key, 0)
    modulus = to_big_int(binary_key[4, i])

    j = read_int(binary_key, i + 4)
    public_exponent = to_big_int(binary_key[i + 8, j])

    @p_key = make_p_key(modulus, public_exponent)
  end

  def self.read_int(binary_string, offset)
    binary_string[offset, 4].unpack('N')[0]
  end

  def self.to_big_int(binary_string)
    binary_string.unpack('C*').reverse.each.with_index.reduce(0) do |n, (byte, i)|
      n | byte << i * 8
    end
  end

  def self.make_p_key(modulus, public_exponent)
    elements = [OpenSSL::ASN1::Integer.new(modulus), OpenSSL::ASN1::Integer.new(public_exponent)]
    sequence = OpenSSL::ASN1::Sequence.new(elements)
    OpenSSL::PKey::RSA.new(sequence.to_der)
  end

  def self.encode64(data)
    Base64.strict_encode64(data).gsub('+', '-').gsub('/', '_')
  end
end
