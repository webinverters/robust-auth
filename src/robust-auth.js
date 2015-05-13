/**
 * @module robust-auth
 * @summary: Provides fine-grained authentication services for maximum flexibility and comfort.
 *
 * @description:
 *
 * Author: Justin Mooser
 * Created On: 2015-05-12.
 * @license Apache-2.0
 */

"use strict";

var _ = require('lodash');
/**
 * @note You cannot deauthenticate a token.  It will expire in 1 day by default, but until then it cannot be
 * voided unless you delete the entire user who the token belongs to.
 *
 * @constraints The user object returned by the dal.getUserTokenInfo() must have an id property.
 * @param config
 * @param dal - specifically dal.getUserTokenInfo, dal.delete, dal.create
 * @param logger
 * @returns {{}}
 */
module.exports = function construct(config, dal, encryption, logger) {
  var m = {};

  encryption = encryption || require('jwt-simple');
  var defaultRoutesNotRequiringAuthentication = {
    '/token': true,
    '/user': true
  };

  config = config ? _.cloneDeep(config) : {};
  config = _.defaults(config, {
    enableCORS: true,
    attachEndpoints: true,
    attachMiddleware: true,
    secret: null,  // purposely do not set a default so the security is not weakened by user's forgetting to change the default.
    routesNotRequiringAuthentication: defaultRoutesNotRequiringAuthentication,
    tokenExpireDurationSecs: 60*60*24*1 // one day by default.
  });

  if (!config.secret) throw "robust-auth: you must specify a secret key if you plan to win.";
  if (config.secret.length < 14) throw "robust-auth: your secret must be longer than 14 characters in length.";

  if (config.attachEndpoints) {
    _.extend(config.routesNotRequiringAuthentication, defaultRoutesNotRequiringAuthentication);
  }

  if (!dal.create) throw 'robust-auth: dal.create must exist and return a promise.';
  if (!dal.getUserTokenInfo) throw 'robust-auth: dal.getUserTokenInfo must exist and return a promise.';
  if (!dal.delete) throw 'robust-auth: dal.delete must exist and return a promise.';

  function authenticate(req, res) {
    return m.authenticate(req.body.key, req.body.secret)
      .then(function(token) {
        if (token) {
          res.send({token: token});
        } else {
          res.status(401).send();
        }
      });
  }

  m.authenticate = function(userId, pass) {
    return dal.getUserTokenInfo(userId).then(function (user) {
      if (m.validatePassword(pass, user.secretHash)) {
        var token = m.createUserToken(user);
        return token;
      } else {
        return null;
      }
    });
  };

  m.validatePassword = function(password, hash) {
    // use the same encryption for both jwt and passwords.
    if (encryption.encode(password, config.secret) == hash) {
      return true;
    }
    return false;
  };

  m.createUserToken = function(userInfo) {
    var u = _.cloneDeep(userInfo);
    delete u.password;
    u.tokenExpiry = new Date().getTime() + (1000*config.tokenExpireDurationSecs);

    return encryption.encode(u, config.secret);
  };

  function registerUser(req, res) {
    logger.debug('Registering User...', req.body);
    return m.registerUser(req.body)
      .then(function(result) {
        res.status(200).send(result);
      })
      .catch(function(err) {
        res.status(400).send(err);
      });
  }

  m.registerUser = function(user) {
    user.secretHash = encryption.encode(user.password || user.secret, config.secret);
    delete user.password;
    delete user.secret;
    return dal.create('user', user)
      .catch(function(err) {
        logger.logError('robust-auth: failed to register a new user.  "dal.create"', err);
        throw err;
      });
  };

  /**
   * Detects if the user is sending an authenticated request.  If it is, it will set req.user and req.session.user details.
   * @param req
   * @param res
   * @param next
   */
  function authDetectionMiddleware(req, res, next) {
    logger.debug('Running Auth Detection Middleware...', req.body);

    if (req.headers['token']) {
      try {
        req.session.user = req.user = encryption.decode(req.headers['token'], config.secret);
        if (!req.user.id) throw 'AUTH FAILED:USER HAS NO MEMBER: id';
        if (!req.user.tokenExpiry || req.user.tokenExpiry <= new Date().getTime()) {
          logger.log('Expired Token:', req.user);
          res.status(401).send({errorCode: 'expired token'});
        }
        else {
          logger.log('Authenticated User:', req.user.id);
          next();
        }
      } catch (ex) {
        logger.logError('Unexpectedly could not decode a token.', ex);
        res.status(401).send();
        // ensure no user is authenticated.
        req.session.user = req.user = null;
      }
    } else {
      if (config.routesNotRequiringAuthentication[req.path])
        next();

      res.status(401).send();
    }
  }

  m.deleteUser = function(userId) {
    return dal.delete('user', userId)
      .catch(function(err) {
        logger.logError('Failed to delete user.', err);
        throw 'robust-auth: there was an error in a dal method "dal.delete".  This is code you are responsible for.';
      });
  };

  var deleteUser = function(req, res) {
    m.deleteUser(req.user.id)
      .then(function() {
        res.status(200).send();
      })
      .catch(function(err) {
        logger.logError('Failed to delete user:', err);
        res.status(500).send();
      });
  };

  m.attach = function(app, opts) {
    opts = opts || config;

    if (opts.enableCORS) {
      app.use(function(req, res, next) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
        res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
        next();
      });
    }

    // allow cross origin requests
    if (opts.attachEndpoints) {
      app.post('/token', authenticate);
      app.delete('/user', deleteUser);
      app.post('/user', registerUser);
    }

    if (opts.attachMiddleware) {
      app.use(authDetectionMiddleware);
    }
  };

  return m;
};