# frozen_string_literal: true

require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    # AuthProvider strategy for OmniAuth
    # :reek:InstanceVariableAssumption
    class AuthProvider < OmniAuth::Strategies::OAuth2
      option :name, :auth_provider
      option :namespace, nil
      option :provider_ignores_state, true

      def initialize(app, *args, &block)
        super
        protocol = @options[:secure] ? 'https' : 'http'
        client_options = @options.client_options
        namespace = @options[:namespace]

        raise(ArgumentError, "Received wrong number of arguments. #{args.inspect}") unless namespace

        client_options.site = "#{protocol}://#{namespace}"
        client_options.authorize_url = "#{protocol}://#{namespace}/oauth/authorize"
        client_options.token_url = "#{protocol}://#{namespace}/oauth/token"
        client_options.userinfo_url = "#{protocol}://#{namespace}/userinfo"
      end

      def authorize_params
        super.tap do |param|
          redirect_uri = request.params['redirect_uri']
          param[:redirect_uri] = redirect_uri if redirect_uri
        end
      end

      def query_string
        clean_query_string = URI.encode_www_form(CGI.parse(request.query_string).except('code', 'state'))
        clean_query_string.empty? ? '' : "?#{clean_query_string}"
      end

      uid { raw_info['uid'] }

      extra do
        { raw_info: raw_info }
      end

      info do
        {
          email: raw_info['email'],
          client_id: raw_info['client_id'],
          name: [raw_info['first_name'], raw_info['last_name']].join(' ').strip,
          image: raw_info['avatar_url']
        }
      end

      # :nocov:
      def raw_info
        @raw_info ||= access_token.get(options.client_options.userinfo_url).parsed
      end
      # :nocov:
    end
  end
end
