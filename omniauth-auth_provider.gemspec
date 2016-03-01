# -*- encoding: utf-8 -*-
$LOAD_PATH.push File.expand_path('../lib', __FILE__)

Gem::Specification.new do |s|
  s.name        = 'omniauth-auth_provider'
  s.version     = '1.0.1'
  s.authors     = ['AuthProvider', 'Igor Rzegocki']
  s.email       = ['igor@rzegocki.pl']
  s.homepage    = 'https://github.com/ajgon/omniauth-auth_provider'
  s.summary     = 'Omniauth OAuth2 strategy for the AuthProvider platform.'
  s.description = "AuthProvider is an authentication broker that supports social identity providers.\n" \
                  "OmniAuth is a library that standardizes multi-provider authentication for web applications.\n" \
                  'It was created to be powerful, flexible, and do as little as possible.'

  s.rubyforge_project = 'omniauth-auth_provider'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_runtime_dependency 'omniauth-oauth2'

  s.license = 'MIT'
end
