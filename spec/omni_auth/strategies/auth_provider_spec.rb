# frozen_string_literal: true
require 'spec_helper'

describe OmniAuth::Strategies::AuthProvider do
  let(:app) do
    Rack::Builder.new do |b|
      b.use Rack::Session::Cookie, secret: 'abc123'
      b.run ->(_env) { [200, {}, ['Not Found']] }
    end.to_app
  end

  let(:request) do
    request = double('Request')
    allow(request).to receive(:params)
    allow(request).to receive(:cookies)
    allow(request).to receive(:env)
    request
  end

  let(:session) do
    session = double('Session')
    allow(session).to receive(:delete).with('omniauth.state').and_return('state')
  end

  before :each do
    OmniAuth.config.test_mode = true
  end

  after do
    OmniAuth.config.test_mode = false
  end

  subject do
    described_class.new(
      app, 'client_id', 'client_secret', namespace: 'test.dummy-provider.dev'
    ).tap do |strategy|
      allow(strategy).to receive(:request) { request }
    end
  end

  context 'initiation' do
    it 'uses the correct site' do
      expect(subject.options.client_options.site).to eql 'http://test.dummy-provider.dev'
    end

    it 'uses the correct authorize_url' do
      expect(subject.options.client_options.authorize_url).to eq 'http://test.dummy-provider.dev/oauth/authorize'
    end

    it 'uses the correct token_url' do
      expect(subject.options.client_options.token_url).to eq 'http://test.dummy-provider.dev/oauth/token'
    end

    it 'uses the correct userinfo url' do
      expect(subject.options.client_options.userinfo_url).to eq 'http://test.dummy-provider.dev/userinfo'
    end

    it 'raises an ArgumentError error if no namespace passed' do
      expect do
        described_class.new(app, 'client_id', 'client_secret')
      end.to raise_error(ArgumentError)
    end

    it 'returns secure URLs if "secure" option provided' do
      strategy = described_class.new(
        app, 'client_id', 'client_secret', namespace: 'test.dummy-provider.dev', secure: true)

      expect(strategy.options.client_options.authorize_url).to eq 'https://test.dummy-provider.dev/oauth/authorize'
      expect(strategy.options.client_options.token_url).to eq 'https://test.dummy-provider.dev/oauth/token'
      expect(strategy.options.client_options.userinfo_url).to eq 'https://test.dummy-provider.dev/userinfo'
    end
  end

  context 'request phase' do
    before(:each) { get '/auth/auth_provider' }

    it 'authenticate' do
      expect(last_response.status).to eq(200)
    end

    it 'authorize params' do
      allow(subject).to receive(:request) do
        double('Request', params: { 'connection' => 'google-oauth2', 'redirect_uri' => 'redirect_uri' }, env: {})
      end
      expect(subject.authorize_params).to include('state')
      expect(subject.authorize_params).to include('redirect_uri')
    end

    it 'query_string' do
      allow(subject).to receive(:request) do
        double('Request', query_string: 'code=123&state=456&other=789')
      end

      expect(subject.query_string).to eq '?other=789'
    end
  end

  describe 'callback phase' do
    let(:raw_info) do
      {
        'email' => 'user@example.com',
        'client_id' => 'wgpYTrLmRL8DjBjAEk7BWbGc',
        'provider' => 'auth_provider',
        'uid' => 'wgpYTrLmRL8DjBjAEk7BWbGc',
        'first_name' => 'Dummy',
        'last_name' => 'User',
        'avatar_url' => 'http://i.imgur.com/DdxlUu2.jpg'
      }
    end

    before :each do
      allow(subject).to receive(:raw_info) { raw_info }
    end

    context 'info' do
      it 'returns the uid (required)' do
        expect(subject.uid).to eq('wgpYTrLmRL8DjBjAEk7BWbGc')
      end

      it 'returns the email' do
        expect(subject.info[:email]).to eq('user@example.com')
      end

      it 'returns the client_id' do
        expect(subject.info[:client_id]).to eq('wgpYTrLmRL8DjBjAEk7BWbGc')
      end

      it 'returns the name' do
        expect(subject.info[:name]).to eq('Dummy User')
      end

      it 'returns the image' do
        expect(subject.info[:image]).to eq('http://i.imgur.com/DdxlUu2.jpg')
      end

      it 'returns the raw_info in extra' do
        expect(subject.extra[:raw_info]).to eq(raw_info)
      end
    end

    context 'get token' do
      let(:access_token) do
        access_token = double('OAuth2::AccessToken')

        allow(access_token).to receive(:token)
        allow(access_token).to receive(:expires?)
        allow(access_token).to receive(:expires_at)
        allow(access_token).to receive(:refresh_token)
        allow(access_token).to receive(:params)

        access_token
      end

      before :each do
        allow(subject).to receive(:access_token) { access_token }
      end

      it 'returns a Hash' do
        expect(subject.credentials).to be_a(Hash)
      end

      it 'returns the token' do
        allow(access_token).to receive(:token) {
          {
            access_token: 'OTqSFa9zrh0VRGAZHH4QPJISCoynRwSy9FocUazuaU950EVcISsJo3pST11iTCiI',
            token_type: 'bearer'
          } }
        expect(subject.credentials['token'][:access_token])
          .to eq('OTqSFa9zrh0VRGAZHH4QPJISCoynRwSy9FocUazuaU950EVcISsJo3pST11iTCiI')
        expect(subject.credentials['token'][:token_type]).to eq('bearer')
      end
    end
  end
end
