require 'omniauth-oauth2'
require 'multi_json'

module OmniAuth
  module Strategies
    class YouTube < OmniAuth::Strategies::OAuth2

      DEFAULT_SCOPE = "http://gdata.youtube.com"

      option :name, 'youtube'

      option :client_options, {
        :site => 'https://www.youtube.com',
        :authorize_url => 'https://accounts.google.com/o/oauth2/auth',
        :token_url => 'https://accounts.google.com/o/oauth2/token'
      }
      
      def authorize_params
        base_scope_url = "https://www.googleapis.com/auth/"
        super.tap do |params|
          # Read the params if passed directly to omniauth_authorize_path
          %w(scope approval_prompt access_type state hd).each do |k|
            params[k.to_sym] = request.params[k] unless [nil, ''].include?(request.params[k])
          end
          scopes = (params[:scope] || DEFAULT_SCOPE).split(",")
          scopes.map! { |s| s =~ /^https?:\/\// ? s : "#{base_scope_url}#{s}" }
          params[:scope] = scopes.join(' ')
          # This makes sure we get a refresh_token.
          # http://googlecode.blogspot.com/2011/10/upcoming-changes-to-oauth-20-endpoint.html
          params[:access_type] = 'offline' if params[:access_type].nil?
          params[:approval_prompt] = 'force' if params[:approval_prompt].nil?
          # Override the state per request
          session['omniauth.state'] = params[:state] if request.params['state']
        end
      end

      uid { user['id']['$t'] }

      info do
        {
          'uid' => user['id']['$t'],
          'nickname' => user['author'].first['name']['$t'],
          'email'      => verified_email,
          'first_name' => user['yt$firstName'] && user['yt$firstName']['$t'],
          'last_name' => user['yt$lastName'] && user['yt$lastName']['$t'],
          'image' => user['media$thumbnail'] && user['media$thumbnail']['url'],
          'description' => user['yt$description'] && user['yt$description']['$t'],
          'location' => user['yt$location'] && user['yt$location']['$t'],
          'channel_title' => user['title']['$t'],
          'subscribers_count' => user['yt$statistics']['subscriberCount']
        }
      end

      extra do
        { 'user_hash' => user }
      end

      def user
        user_hash['entry']
      end

      def user_hash
        @user_hash ||= MultiJson.decode(@access_token.get("http://gdata.youtube.com/feeds/api/users/default?alt=json").body)
      end

      def user_info
        @raw_info ||= {} # @access_token.get('https://www.googleapis.com/oauth2/v1/userinfo').parsed
      end

      private

      def verified_email
        user_info['verified_email'] ? user_info['email'] : nil
      end

    end
  end
end

OmniAuth.config.add_camelization 'youtube', 'YouTube'
