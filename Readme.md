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

Copyright (C) <2020>  Joshua Alexander Castaneda

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
    

The MIT License (MIT)
Copyright (c) <2010-2012> Ciaran Jessup
    
    Please see original source code and documentation for all software
    covered under this license.