emissary
=========
Simple OAuth & OAuth2 interaction library, utilizing ES6 modules and JavaScript object delegation.  Emissary negotiates the exchange of an authentication code for an access token. Provides simplified client access and allows for construction of more complex apis and OAuth/OAuth2 providers.

Note: OAuth & OAuth 1.0a is still in development.

This was modified from the node-auth library at https://github.com/ciaranj/node-oauth.

Installation
=============

    $ npm i @nonsensecodes/emissary


Example Usage
==============

## OAuth2.0 
```javascript
import emissary from '@nonsensecodes/emissary';

let oauth = Object.create(emissary);

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
    
    Please see original source code and documentation for all other software
    covered under this license.