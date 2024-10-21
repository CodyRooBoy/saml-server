# SAML 2.0 Service Provider

## Configuration and Run Instructions
1. Copy the contents of `.env.example` into `.env` and configure for your environment
2. Add your own SAML certificates (from your identity provider) to `saml_certs` and your SSL certificates to `ssl_certs`
3. Run `npm install` to download required `node_modules`
4. Run `npm run start` to start the SAML 2.0 Service Provider server

## References
- [Passport-SAML](https://github.com/node-saml/passport-saml)
- [Node SAML](https://github.com/node-saml/node-saml)