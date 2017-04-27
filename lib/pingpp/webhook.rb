module Pingpp
  module Webhook
    def self.verify?(request, pub_key=Pingpp.pub_key)
      unless pub_key
        puts 'Warn: ' + 'No Public key provided. ' +
                            'Set your Public key using "Pingpp.pub_key_path = <API-KEY-FILE> ' +
                            'or Pingpp.pub_key = <API-KEY>" ' +
                            'You can get Public key from the Pingpp website: ' +
                            'https://dashboard.pingxx.com/settings/development_info '
        return false
      end

      # raw_data = nil
      # if request.respond_to?('raw_post')
      #   raw_data = request.raw_post
      # elsif request.respond_to?('body')
      #   raw_data = request.body
      # else
      #   return false
      # end

      raw_data = extract_raw_data(request)

      # headers = nil
      # if request.respond_to?('headers')
      #   headers = request.headers
      # elsif request.respond_to?('header')
      #   headers = request.header
      # else
      #   return false
      # end

      headers = extract_headers(request)

      formatted_headers = Util.format_headers(headers)
      return false unless formatted_headers.has_key?(:x_pingplusplus_signature)

      signature = formatted_headers[:x_pingplusplus_signature]

      rsa_public_key = OpenSSL::PKey.read(pub_key)
      rsa_public_key.verify(OpenSSL::Digest::SHA256.new, Base64.decode64(signature), raw_data)
    end

    # A dumbed down version extracted from ActionDispatch::Request#raw_post
    # see actionpack-4.2.7.1/lib/action_dispatch/http/request.rb#251
    def self.extract_raw_data(request)
      body = request.env['rack.input']
      raw_post_body = body.read(request.content_length)
      body.rewind if body.respond_to?(:rewind)
      raw_post_body
    end

    # see actionpack-4.2.7.1/lib/action_dispatch/http/headers.rb#each
    def self.extract_headers(request)
      request.env
    end
  end
end
