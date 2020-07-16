import querystring from 'querystring';
import http from 'http';
import https from 'https';
import URL from 'url';

let OAuth2 = {

  buildOAuth2: function(options) {
    this._clientID = options.clientID;
    this._clientSecret = options.clientSecret;
    this._authorizeURL = options.authorizeURL;
    this._accessTokenURL = options.accessTokenURL;
    this._callbackURL = options.callbackURL,
    this._accessTokenName = "access_token";
    this._authMethod = "Bearer";
    this._customHeaders = {};
    this._useAuthorizationHeaderForGET = false;
  },

  setAccessTokenName: function(name) {
    this._accessTokenName = name;
  },

  setAuthMethod: function(authMethod) {
    this._authMethod = authMethod;
  },

  useAuthorizationHeaderforGET: function(useIt) {
    this._useAuthorizationHeaderForGET = useIt;
  },

  _getAccessTokenURL: function() {
    return this._baseSite + this._accessTokenURL; /* + "?" + querystring.stringify(params); */
  },
  
  _chooseHTTPLibrary: (parsedUrl) => {
    let http_library = https;
    // As this is OAUth2, we *assume* https unless told explicitly otherwise.
    if (parsedUrl.protocol != "https:") {
      http_library = http;
    }
    return http_library;
  },
  
  buildAuthHeader: function(token) {
    return `${this._authMethod} ${token}`;
  },
  
  getOAuthAccessToken: function(code, callback) {
    let params = {
      'client_id': this._clientID,
      'client_secret': this._clientSecret,
      'grant_type': 'authorization_code',
      'redirect_uri': this._callbackURL,
      'scope': 'the scopes',
      'code': code
    }
    
    params.code = (params.grant_type === 'refresh_token') ? 'refresh_token' : code;
  
    let post_data = querystring.stringify(params);
    
    let post_headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    this._request("POST", this._accessTokenURL, post_headers, post_data, null, (error, result, response) => {
      if (error) {
        callback(error);
      } else {
        let results;
        if (result.startsWith('undefined')) {
          // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07, responses
          // should be in JSON. However both Facebook + Github currently use rev05
          // of the spec and neither seem to specify a content-type correctly in
          // their response headers. Also, data returned from Discord will not
          // parse into a usable object. So we chop it up to make it work.
          let slicedUp = result.slice(9);
          results = JSON.parse(slicedUp);
        } else {
          results = JSON.parse(result);
        }
        // console.log('results:', results);
        let accessToken = results["access_token"];
        let refreshToken = results["refresh_token"];
        // delete results["refresh_token"];
        callback(null, accessToken, refreshToken, params, results); // callback results =-=
      }
    });
  },

  _request: function(method, url, headers, post_body, accessToken, callback) {

    let parsedUrl = URL.parse( url, true );
    if (parsedUrl.protocol == "https:" && !parsedUrl.port) {
      parsedUrl.port = 443;
    }
    
    let http_library = this._chooseHTTPLibrary(parsedUrl);
  
    let realHeaders = {};
    for (let key in this._customHeaders) {
      realHeaders[key] = this._customHeaders[key];
    }
    if (headers) {
      for (let key in headers) {
        realHeaders[key] = headers[key];
      }
    }
    realHeaders['Host'] = parsedUrl.host;
  
    if (!realHeaders['User-Agent']) {
      realHeaders['User-Agent'] = 'Node-oauth';
    }
  
    if (post_body) {
      if (Buffer.isBuffer(post_body)) {
        realHeaders["Content-Length"] = post_body.length;
      } else {
        realHeaders["Content-Length"] = Buffer.byteLength(post_body);
      }
    } else {
      realHeaders["Content-length"] = 0;
    }
  
    if (accessToken && !('Authorization' in realHeaders)) {
      if (!parsedUrl.query) parsedUrl.query = {};
      parsedUrl.query[this._accessTokenName] = accessToken;
    }
  
    let queryStr = querystring.stringify(parsedUrl.query);
    if (queryStr) queryStr =  "?" + queryStr;
    let options = {
      host: parsedUrl.hostname,
      port: parsedUrl.port,
      path: parsedUrl.pathname + queryStr,
      method: method,
      headers: realHeaders
    }
  
    this._executeRequest(http_library, options, post_body, callback);
  },

  _executeRequest: function(http_library, options, post_body, callback) {
    // Some hosts *cough* google appear to close the connection early / send no content-length header
    // allow this behaviour.
    let allowEarlyClose = function isAnEarlyCloseHost(options) {
      let hostName = options.host;
      return hostName && hostName.match(".*google(apis)?.com$")
    }
    let callbackCalled = false;
    
    function passBackControl(response, result) {
      
      if (!callbackCalled) {
        callbackCalled = true;
        if (!(response.statusCode >= 200 && response.statusCode <= 299) && (response.statusCode != 301) && (response.statusCode != 302)) {
          callback({ statusCode: response.statusCode, data: result });
        } else {
          callback(null, result, response);
        }
      }
    }

    let result;
  
    let request = http_library.request(options);
    request.on('response', (response) => {
      response.on("data", (chunk) => {
        result+= chunk;
      });
      response.on("close", function (err) {
        if( allowEarlyClose ) {
          passBackControl( response, result );
        }
      });
      response.addListener("end", () => {
        passBackControl(response, result);
      });
    });
    request.on('error', (e) => {
      callbackCalled = true;
      callback(e);
    });
  
    if ((options.method == 'POST' || options.method == 'PUT') && post_body) {
       request.write(post_body);
    }
    request.end();
  },
  
  getUserResources: function(url, accessToken, callback) {
    if (this._useAuthorizationHeaderForGET) {
      var headers = { 'Authorization': this.buildAuthHeader(accessToken) }
      accessToken = null;
    } else {
      headers = {};
    }
    this._request("GET", url, headers, "", accessToken, callback);
  }
}

export { OAuth2 };