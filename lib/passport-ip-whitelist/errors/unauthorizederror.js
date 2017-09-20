/**
 * `BadRequestError` error.
 *
 * @api public
 */
function UnauthorizedError(message) {
    Error.call(this);
    Error.captureStackTrace(this, arguments.callee);
    this.name = 'UnauthorizedError';
    this.message = message || null;
    this.code = 401;
}

/**
 * Inherit from `Error`.
 */
UnauthorizedError.prototype.__proto__ = Error.prototype;

/**
 * Expose `BadRequestError`.
 */
module.exports = UnauthorizedError;