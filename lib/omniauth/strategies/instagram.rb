require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Instagram < OmniAuth::Strategies::OAuth2
      
      option :name, 'instagram'

      option :client_options, {
        :site => 'https://instagram.com',
        :authorize_url => 'https://instagram.com/oauth/authorize',
        :token_url => 'https://instagram.com/oauth/access_token'
      }

      option :authorize_params, {
        :scope => 'basic',
        :response_type => 'code'
      }

      option :token_params, {
        :parse => :json
      }

      option :access_token_options, {
        :header_format => 'OAuth %s',
        :param_name => 'access_token'
      }

      def request_phase
        super
      end

      uid { raw_info['id'] }

      info do
        {
          'username' => raw_info['username'],
          'name'     => raw_info['full_name'],
          'profile_picture'    => raw_info['profile_picture']
        }
      end

      def raw_info
        @data ||= access_token.params["user"]
        unless @data
          access_token.options[:mode] = :query
          access_token.options[:param_name] = "access_token"
          @data ||= access_token.get('/v1/users/self').parsed['data'] || {}
        end
        @data
      end

    end
  end
end
