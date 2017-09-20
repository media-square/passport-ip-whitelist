"use strict";
const passport = require('passport')
    , util = require('util')
    , ip = require('ip')
    , _ = require('lodash')
    , BadRequestError = require('./errors/badrequesterror')
    , UnauthorizedError = require('./errors/unauthorizederror')
;

const defaultOptions = {
    "tokenValidation": false,
    "defaultUser": {
        "id": -1,
        "admin": false,
        "scope": [],
        "token": null
    },
    "users": []
};


function Strategy(options, verify) {
    if (typeof options == 'function') {
        verify = options;
        options = {};
    }
    if (!verify) {
        throw new Error('ip whitelist authentication strategy requires a verify function');
    }

    passport.Strategy.call(this);
    this.name = 'ipwhitelist';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
}


/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
    const settings = _.defaultsDeep(options.whitelist || {}, defaultOptions );
    const remoteIp = getRemoteIpFromRequest(req);
    if (!settings.users) {
        return this.fail(new BadRequestError('No IP whitelist provided'));
    }
    else if (!(settings.users instanceof Array)) {
        return this.fail(new BadRequestError('Provided IP whitelist is not an array'));
    }
    else if (!remoteIp) {
        return this.fail(new BadRequestError('Can\'t find remote IP address in request'));
    }
    const user = findUser(remoteIp, settings.users);
    if (!user) {
        return this.fail(new UnauthorizedError('Remote IP address not authenticated'));
    }
    if(settings.tokenValidation){
        const requestToken = req.headers.token || req.query.token || req.body.token || false;
        if( !requestToken){
            return this.fail(new BadRequestError('Token is required'));
        }
        if(user.token !== requestToken){
            return this.fail(new UnauthorizedError(settings.unauthorizedMessage || 'Provided token is invalid'));
        }
    }
    if (settings.defaultUser) {
        _.defaults(user,settings.defaultUser);
    }

    let verified = function (err, user, info) {
        if (err) { return this.error(err); }
        if (!user) { return this.fail(info); }
        this.success(user, info);
    }.bind(this);

    try {
        if (this._passReqToCallback) {
            this._verify(req, user, verified);
        } else {
            this._verify(user, verified);
        }
    } catch (Error) {
        return this.error(Error);
    }

    /**
     * Get the remote IP address based on connection or forwarded IP Address
     * @param request
     * @returns real remote IP address or false
     */
    function getRemoteIpFromRequest(req) {
        const remoteIp = req.header("X-Forwarded-For") || req.connection.remoteAddress;
        if (remoteIp) {
            return remoteIp.split(",")
                .shift();
        }
        return false;
    }

    /**
     * Map user with provided IP Address
     * @param remoteIp of the request
     * @param whiteList array
     * @returns user within whitelist
     */
    function findUser(remoteIp, whiteList) {
        let user = false;
        // Loop through the whitelist
        //
        whiteList.forEach(function (item) {
            // Check if provided IP has CIDR notation
            //
            if (item.ip.indexOf("/") !== -1) {
                const ipCidrSubnet = ip.cidrSubnet(item.ip);
                if (ipCidrSubnet.contains(remoteIp)) {
                    user = item.user;
                }
            }
            else if( ip.isEqual(item.ip, remoteIp) ){
                user = item.user;
            }
            // Matching IP address found, stop looping
            //
            if (user) {
                return false;
            }
        });
        return user;
    }
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
