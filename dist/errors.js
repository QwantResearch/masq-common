'use strict';

var _classCallCheck2 = require('babel-runtime/helpers/classCallCheck');

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = require('babel-runtime/helpers/createClass');

var _createClass3 = _interopRequireDefault(_createClass2);

var _possibleConstructorReturn2 = require('babel-runtime/helpers/possibleConstructorReturn');

var _possibleConstructorReturn3 = _interopRequireDefault(_possibleConstructorReturn2);

var _inherits2 = require('babel-runtime/helpers/inherits');

var _inherits3 = _interopRequireDefault(_inherits2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var ERRORS = {
  NOT_LOGGED_IN: 'Not logged into Masq',
  NOT_CONNECTED: 'Not connected to Masq',
  UNABLE_TO_DECRYPT: 'Unable to decrypt data',
  WRONG_MESSAGE: 'Wrong message received',
  MASQ_ACCESS_REFUSED_BY_USER: 'Masq access refused by the user',
  INVALID_KEY: 'Invalid key'
};

var MasqError = function (_Error) {
  (0, _inherits3.default)(MasqError, _Error);

  function MasqError(type, details) {
    (0, _classCallCheck3.default)(this, MasqError);

    var _this = (0, _possibleConstructorReturn3.default)(this, (MasqError.__proto__ || Object.getPrototypeOf(MasqError)).call(this));

    _this.type = type;
    _this.details = details;
    return _this;
  }

  (0, _createClass3.default)(MasqError, [{
    key: 'getMessage',
    value: function getMessage() {
      if (!this.type) {
        return 'Unknown error';
      }
      var msg = ERRORS[this.type];
      if (!msg) {
        msg = 'Unknown error with type "' + this.type + '"';
      }

      if (this.details) {
        msg = msg + ' : ' + this.details;
      }

      return msg;
    }
  }]);
  return MasqError;
}(Error);

/**
   * Use this fonction to check if the required parameters
   * are present in the received object.
   * @param {object} obj - The object we want to check
   * @param {array} parameters - The array with all the keys we want to test
   * @returns {masqError}
   */


var checkObject = function checkObject(obj, parameters) {
  for (var i in parameters) {
    if (typeof obj[parameters[i]] !== 'boolean') {
      if (!obj[parameters[i]] || obj[parameters[i]] === '') {
        var error = {
          message: 'The parameter ' + parameters[i] + ' is required',
          name: ERRORS.WRONGPARAMETER
        };
        throw error;
      }
    }
  }
};

module.exports.checkObject = checkObject;
module.exports.ERRORS = ERRORS;
module.exports.MasqError = MasqError;