node-oauth
===========
A super simple oauth2 API for node.js, set up as an ES Module with object delegation. This API allows users to authenticate against OAUTH2 providers, and thus act as OAuth2 consumers.

This was modified from the node-auth library at https://github.com/ciaranj/node-oauth.

Installation
============== 

    $ npm install @nonsensetwice/oauth2


Example Usage
==========

## OAuth2.0 
```javascript
import { OAuth2 } from 'oauth2';

let oauth = Object.create(OAuth2);

oauth.buildOAuth2({
  clientID: 'your client id',
  clientSecret: 'your client secret',
  authorizeURL: 'full authorize url',
  accessTokenURL: 'full token url',
  callbackURL: 'your callback url'
});

oauth.getOAuthAccessToken(code, callback);
```

Please see original repo for better detail and more use-cases.