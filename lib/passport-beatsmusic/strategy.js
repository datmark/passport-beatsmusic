/**
 * Module dependencies.
 */
var util = require('util')
  , url = require('url')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Beats Music authentication strategy authenticates requests by delegating to
 * Beats Music using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and `beatsmusic` object, which contains additional info as outlined
 * here: https://developer.beatsmusic.com/docs/read/getting_started/Web_Server_Applications.
 * The callback should then call the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Beats Music application's client ID
 *   - `clientSecret`  your Beats Music application's App Secret
 *   - `callbackURL`   URL to which Beats Music will redirect the user after granting authorization
 *
 * Examples:
 *     BeatsMusicStrategy = require('passport-beatsmusic').Strategy;
 *
 *     ...
 *
 *     passport.use(new BeatsMusicStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-super-secret'
 *         callbackURL: 'https://www.example.net/auth/beatsmusic/callback'
 *       },
 *       function(accessToken, refreshToken, beatsmusic, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.baseURL = options.baseURL || 'https://partner.api.beatsmusic.com';
  options.apiVersion = options.apiVersion || 'v1';
  options.baseOauth2URL = options.baseOauth2URL || options.baseURL + '/' + options.apiVersion + '/oauth2'
  options.authorizationURL = options.authorizationURL || options.baseOauth2URL + '/authorize';
  options.tokenURL = options.tokenURL || options.baseOauth2URL + '/token';
  options.scopeSeparator = options.scopeSeparator || ',';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'beatsmusic';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
OAuth2Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;

  if (req.query && req.query.error) {
    // TODO: Error information pertaining to OAuth 2.0 flows is encoded in the
    //       query parameters, and should be propagated to the application.
    return this.fail();
  }

  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req), callbackURL);
    }
  }

  if (req.query && req.query.code) {
    var code = req.query.code;

    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the percent-encoded data sent in
    //       the body of the access token request.  This appears to be an
    //       artifact from an earlier draft of OAuth 2.0 (draft 22, as of the
    //       time of this writing).  This parameter is not necessary, but its
    //       presence does not appear to cause any issues.
    this._oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: callbackURL },
      function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(new InternalOAuthError('failed to obtain access token', err)); }

        function verified(err, user, info) {
          if (err) { return self.error(err); }
          if (!user) { return self.fail(info); }
          self.success(user, info);
        }

        // Generate the additional beatsmusic object
        var beatsmusic = {};
        beatsmusic.jsonrpc = params.jsonrpc || null;
        beatsmusic.id = params.id || null;
        beatsmusic.code = params.code || null;
        if (params.result) {
            beatsmusic.return_type = params.result.return_type || null;
            beatsmusic.access_token = params.result.access_token || null;
            beatsmusic.token_type = params.result.token_type || null;
            beatsmusic.expires_in = params.result.expires_in || null;
            beatsmusic.refresh_token = params.result.refresh_token || null;
            beatsmusic.scope = params.result.scope || null;
            beatsmusic.state = params.result.state || null;
            beatsmusic.uri = params.result.uri || null;
            beatsmusic.extended = params.result.extended || null;
        }

        if (self._passReqToCallback) {
          self._verify(req, accessToken, refreshToken, beatsmusic, verified);
        } else {
          self._verify(accessToken, refreshToken, beatsmusic, verified);
        }
      }
    );
  } else {
    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the query portion of the URL.
    //       This appears to be an artifact from an earlier draft of OAuth 2.0
    //       (draft 22, as of the time of this writing).  This parameter is not
    //       necessary, but its presence does not appear to cause any issues.

    var params = this.authorizationParams(options);
    params['response_type'] = 'code';
    params['redirect_uri'] = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) { params.state = state; }

    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
