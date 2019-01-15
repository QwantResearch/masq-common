'use strict';

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = require('babel-runtime/helpers/asyncToGenerator');

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var _crypto = require('./crypto');

var _errors = require('./errors');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var promisifyAll = require('bluebird').promisifyAll;
var hyperdb = require('hyperdb');
var rai = require('random-access-idb');

function createPromisifiedHyperDB(name, hexKey) {
  var keyBuffer = hexKey ? Buffer.from(hexKey, 'hex') : null;
  return promisifyAll(hyperdb(rai(name), keyBuffer, { valueEncoding: 'json', firstNode: true }));
}

function dbReady(db) {
  return new Promise(function (resolve, reject) {
    db.on('ready', function () {
      resolve();
    });
  });
}

function dbExists(dbName) {
  return new Promise(function (resolve, reject) {
    var req = window.indexedDB.open(dbName);
    var existed = true;
    req.onsuccess = function () {
      req.result.close();
      if (!existed) {
        window.indexedDB.deleteDatabase(dbName);
      }
      resolve(existed);
    };
    req.onupgradeneeded = function () {
      existed = false;
    };
    req.onerror = function (err) {
      reject(err);
    };
  });
}

function getHashParams(link) {
  var url = new URL(link);
  var hash = url.hash.slice(2);
  var hashParamsArr = JSON.parse(Buffer.from(hash, 'base64').toString('utf8'));
  if (!Array.isArray(hashParamsArr) || hashParamsArr.length !== 4) {
    throw new Error('Wrong login URL');
  }
  var hashParamsObj = {
    appName: hashParamsArr[0],
    requestType: hashParamsArr[1],
    channel: hashParamsArr[2],
    key: hashParamsArr[3]
  };
  hashParamsObj.key = Buffer.from(hashParamsObj.key, 'base64');
  return hashParamsObj;
}

/**
   * Get a value
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} key - The key name
   * @returns {Promise}
   */
var get = function () {
  var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(db, encKey, key) {
    var node, dec;
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            if (db instanceof hyperdb) {
              _context.next = 2;
              break;
            }

            throw new _errors.MasqError(_errors.ERRORS.NO_DB);

          case 2:
            if (encKey) {
              _context.next = 4;
              break;
            }

            throw new _errors.MasqError(_errors.ERRORS.NO_ENCRYPTION_KEY);

          case 4:
            _context.next = 6;
            return db.getAsync(key);

          case 6:
            node = _context.sent;

            if (node) {
              _context.next = 9;
              break;
            }

            return _context.abrupt('return', null);

          case 9:
            _context.next = 11;
            return (0, _crypto.decrypt)(encKey, node.value);

          case 11:
            dec = _context.sent;
            return _context.abrupt('return', dec);

          case 13:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, undefined);
  }));

  return function get(_x, _x2, _x3) {
    return _ref.apply(this, arguments);
  };
}();

/**
   * Put a new value in the db
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} key - The key name
   * @param {any} value - The value to insert
   * @returns {Promise}
   */
var put = function () {
  var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(db, encKey, key, value) {
    var enc;
    return _regenerator2.default.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            if (db instanceof hyperdb) {
              _context2.next = 2;
              break;
            }

            throw new _errors.MasqError(_errors.ERRORS.NO_DB);

          case 2:
            if (encKey) {
              _context2.next = 4;
              break;
            }

            throw new _errors.MasqError(_errors.ERRORS.NO_ENCRYPTION_KEY);

          case 4:
            _context2.next = 6;
            return (0, _crypto.encrypt)(encKey, value);

          case 6:
            enc = _context2.sent;
            return _context2.abrupt('return', db.putAsync(key, enc));

          case 8:
          case 'end':
            return _context2.stop();
        }
      }
    }, _callee2, undefined);
  }));

  return function put(_x4, _x5, _x6, _x7) {
    return _ref2.apply(this, arguments);
  };
}();

/**
   * List all keys and values
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} prefix - Prefix
   * @returns {Promise}
   */
var list = function () {
  var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee4(db, encKey, prefix) {
    var list, decList, reformattedDic;
    return _regenerator2.default.wrap(function _callee4$(_context4) {
      while (1) {
        switch (_context4.prev = _context4.next) {
          case 0:
            if (db instanceof hyperdb) {
              _context4.next = 2;
              break;
            }

            throw new _errors.MasqError(_errors.ERRORS.NO_DB);

          case 2:
            if (encKey) {
              _context4.next = 4;
              break;
            }

            throw new _errors.MasqError(_errors.ERRORS.NO_ENCRYPTION_KEY);

          case 4:
            _context4.next = 6;
            return db.listAsync(prefix);

          case 6:
            list = _context4.sent;

            if (!(list.length === 1 && list[0].key === '' && list[0].value === null)) {
              _context4.next = 9;
              break;
            }

            return _context4.abrupt('return', {});

          case 9:
            _context4.next = 11;
            return Promise.all(list.map(function () {
              var _ref4 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(elt) {
                return _regenerator2.default.wrap(function _callee3$(_context3) {
                  while (1) {
                    switch (_context3.prev = _context3.next) {
                      case 0:
                        _context3.t0 = elt.key;
                        _context3.next = 3;
                        return (0, _crypto.decrypt)(encKey, elt.value);

                      case 3:
                        _context3.t1 = _context3.sent;
                        return _context3.abrupt('return', {
                          key: _context3.t0,
                          value: _context3.t1
                        });

                      case 5:
                      case 'end':
                        return _context3.stop();
                    }
                  }
                }, _callee3, undefined);
              }));

              return function (_x11) {
                return _ref4.apply(this, arguments);
              };
            }()));

          case 11:
            decList = _context4.sent;
            reformattedDic = decList.reduce(function (dic, e) {
              var el = Array.isArray(e) ? e[0] : e;
              dic[el.key] = el.value;
              return dic;
            }, {});
            return _context4.abrupt('return', reformattedDic);

          case 14:
          case 'end':
            return _context4.stop();
        }
      }
    }, _callee4, undefined);
  }));

  return function list(_x8, _x9, _x10) {
    return _ref3.apply(this, arguments);
  };
}();

module.exports = {
  dbReady: dbReady,
  dbExists: dbExists,
  createPromisifiedHyperDB: createPromisifiedHyperDB,
  getHashParams: getHashParams,
  get: get,
  put: put,
  list: list
};