'use strict';

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = require('babel-runtime/helpers/asyncToGenerator');

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var _errors = require('./errors');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var genRandomBuffer = function genRandomBuffer() {
  var len = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 16;

  var values = window.crypto.getRandomValues(new Uint8Array(len));
  return Buffer.from(values);
};

/**
 *  Return a buffer of an UInt8Array
 *  This is only used for regression test,
 *  we check if Uint8array and Buffer.from
 *  have the same behaviour with the webCryptoApi
 *  Buffer.from is not available (without babelify) in
 *  the test file.
 *
 * @param {Uint8Array} arr
 * @returns {Buffer}
 */
var getBuffer = function getBuffer(arr) {
  return Buffer.from(arr);
};

/**
 @typedef HashedPassphrase
 @type {Object}
 @property {string} storedHash - The hash of the derived key (format: hex string)
 @property {string} hashAlgo - The hash algo for the PBKDF2 and the final hash to store it
 @property {sring} salt - The salt used to derive the key (format: hex string)
 @property {Number} iterations - The iteration # used during key derivation
 */

var _checkPassphrase = function _checkPassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase === '') {
    throw (0, _errors.generateError)(_errors.ERRORS.NOPASSPHRASE);
  }
};

var _checkCryptokey = function _checkCryptokey(key) {
  if (!key.type || key.type !== 'secret') {
    throw (0, _errors.generateError)(_errors.ERRORS.NOCRYPTOKEY);
  }
};

/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hash] The hash function used for derivation
 * @returns {Promise<Uint8Array>}   A promise that contains the derived key
 */
var deriveBits = function deriveBits(passPhrase, salt, iterations, hash) {
  // Always specify a strong salt
  if (iterations < 10000) {
    console.warn('The iteration number is less than 10000, increase it !');
  }

  return window.crypto.subtle.importKey('raw', typeof passPhrase === 'string' ? Buffer.from(passPhrase) : passPhrase, 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
    return window.crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: salt || new Uint8Array([]),
      iterations: iterations || 100000,
      hash: hash || 'SHA-256'
    }, baseKey, 128);
  }).then(function (derivedKey) {
    return new Uint8Array(derivedKey);
  });
};

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} msg The message
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise<Uint8Array>}   A promise that contains the hash as a Uint8Array
 */
var hash256 = function () {
  var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(msg) {
    var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'SHA-256';
    var digest;
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            _context.next = 2;
            return window.crypto.subtle.digest({
              name: 'SHA-256'
            }, typeof msg === 'string' ? Buffer.from(msg) : msg);

          case 2:
            digest = _context.sent;
            return _context.abrupt('return', new Uint8Array(digest));

          case 4:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, undefined);
  }));

  return function hash256(_x3) {
    return _ref.apply(this, arguments);
  };
}();

/**
 * Derive a passphrase and return the object to store
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @returns {Promise<HashedPassphrase>}   A promise that contains the derived key
 */
var derivePassphrase = function () {
  var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(passPhrase, salt) {
    var _salt, iterations, hashedValue;

    return _regenerator2.default.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            _checkPassphrase(passPhrase);
            _salt = salt || genRandomBuffer(16);
            iterations = 100000;
            _context2.next = 5;
            return deriveBitsAndHash(passPhrase, _salt, iterations);

          case 5:
            hashedValue = _context2.sent;
            return _context2.abrupt('return', {
              salt: Buffer.from(_salt).toString('hex'),
              iterations: iterations,
              hashAlgo: 'SHA-256',
              storedHash: Buffer.from(hashedValue).toString('hex')
            });

          case 7:
          case 'end':
            return _context2.stop();
        }
      }
    }, _callee2, undefined);
  }));

  return function derivePassphrase(_x4, _x5) {
    return _ref2.apply(this, arguments);
  };
}();

/**
 * Derive the passphrase with PBKDF2 and hash the output with the given hash function
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hash] The hash function used for derivation and final hash computing
 * @returns {Promise<Uint8Array>}   A promise that contains the hashed derived key
 */
var deriveBitsAndHash = function () {
  var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(passPhrase, salt, iterations, hash) {
    var derivedPassphrase, finalHash;
    return _regenerator2.default.wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            _context3.next = 2;
            return deriveBits(passPhrase, salt, iterations, hash);

          case 2:
            derivedPassphrase = _context3.sent;
            _context3.next = 5;
            return hash256(derivedPassphrase);

          case 5:
            finalHash = _context3.sent;
            return _context3.abrupt('return', finalHash);

          case 7:
          case 'end':
            return _context3.stop();
        }
      }
    }, _callee3, undefined);
  }));

  return function deriveBitsAndHash(_x6, _x7, _x8, _x9) {
    return _ref3.apply(this, arguments);
  };
}();

var requiredParameterHashedPassphrase = ['salt', 'iterations', 'storedHash', 'hashAlgo'];

/**
 * Check a given passphrase by comparing it to the stored hash value (in HashedPassphrase object)
 *
 * @param {string} passphrase The passphrase
 * @param {HashedPassphrase} hashedPassphrase The HashedPassphrase object
 * @returns {Promise<Boolean>}   A promise
 */
var checkPassphrase = function () {
  var _ref4 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee4(passPhrase, hashedPassphrase) {
    var salt, iterations, storedHash, hashAlgo, hashCandidate;
    return _regenerator2.default.wrap(function _callee4$(_context4) {
      while (1) {
        switch (_context4.prev = _context4.next) {
          case 0:
            _checkPassphrase(passPhrase);
            (0, _errors.checkObject)(hashedPassphrase, requiredParameterHashedPassphrase);
            salt = hashedPassphrase.salt, iterations = hashedPassphrase.iterations, storedHash = hashedPassphrase.storedHash, hashAlgo = hashedPassphrase.hashAlgo;
            _context4.next = 5;
            return deriveBitsAndHash(passPhrase, Buffer.from(salt, 'hex'), iterations, hashAlgo);

          case 5:
            hashCandidate = _context4.sent;
            return _context4.abrupt('return', Buffer.from(hashCandidate).toString('hex') === storedHash);

          case 7:
          case 'end':
            return _context4.stop();
        }
      }
    }, _callee4, undefined);
  }));

  return function checkPassphrase(_x10, _x11) {
    return _ref4.apply(this, arguments);
  };
}();

/**
   * Generate an AES key based on the cipher mode and keysize
   * @param {boolean} [extractable] - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {Promise<CryptoKey>} - The generated AES key.
   */
var genAESKey = function genAESKey(extractable, mode, keySize) {
  return window.crypto.subtle.generateKey({
    name: mode || 'AES-GCM',
    length: keySize || 128
  }, extractable || true, ['decrypt', 'encrypt']);
};

/**
  * Export a CryptoKey into a raw|jwk key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @param {string} [type] - The type of the exported key
  * @returns {arrayBuffer|Object} - The raw key or the key as a jwk format
  */
var exportKey = function () {
  var _ref5 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee5(key) {
    var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';
    var exportedKey;
    return _regenerator2.default.wrap(function _callee5$(_context5) {
      while (1) {
        switch (_context5.prev = _context5.next) {
          case 0:
            _context5.next = 2;
            return window.crypto.subtle.exportKey(type, key);

          case 2:
            exportedKey = _context5.sent;

            if (!(type === 'raw')) {
              _context5.next = 5;
              break;
            }

            return _context5.abrupt('return', new Uint8Array(exportedKey));

          case 5:
            return _context5.abrupt('return', exportedKey);

          case 6:
          case 'end':
            return _context5.stop();
        }
      }
    }, _callee5, undefined);
  }));

  return function exportKey(_x13) {
    return _ref5.apply(this, arguments);
  };
}();

/**
  * Import a raw|jwk as a CryptoKey
  *
  * @param {arrayBuffer|Object} key - The key
  * @param {string} [type] - The type of the key to import ('raw', 'jwk')
  * @param {string} [mode] - The mode of the key to import (default 'AES-GCM')
  * @returns {arrayBuffer|Object} - The cryptoKey
  */
var importKey = function importKey(key) {
  var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';
  var mode = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'AES-GCM';

  return window.crypto.subtle.importKey(type, key, { name: mode }, true, ['encrypt', 'decrypt']);
};

/**
 * Decrypt buffer
 *
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only AES-GCM)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The decrypted buffer
 */
var decryptBuffer = function () {
  var _ref6 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee6(key, data, cipherContext) {
    var decrypted;
    return _regenerator2.default.wrap(function _callee6$(_context6) {
      while (1) {
        switch (_context6.prev = _context6.next) {
          case 0:
            _context6.next = 2;
            return window.crypto.subtle.decrypt(cipherContext, key, data);

          case 2:
            decrypted = _context6.sent;
            return _context6.abrupt('return', new Uint8Array(decrypted));

          case 4:
          case 'end':
            return _context6.stop();
        }
      }
    }, _callee6, undefined);
  }));

  return function decryptBuffer(_x16, _x17, _x18) {
    return _ref6.apply(this, arguments);
  };
}();

/**
 * Encrypt buffer
 *
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {ArrayBuffer} data - Data to encrypt
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only AES-GCM)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The encrypted buffer
 */
var encryptBuffer = function () {
  var _ref7 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee7(key, data, cipherContext) {
    var encrypted;
    return _regenerator2.default.wrap(function _callee7$(_context7) {
      while (1) {
        switch (_context7.prev = _context7.next) {
          case 0:
            _context7.next = 2;
            return window.crypto.subtle.encrypt(cipherContext, key, data);

          case 2:
            encrypted = _context7.sent;
            return _context7.abrupt('return', new Uint8Array(encrypted));

          case 4:
          case 'end':
            return _context7.stop();
        }
      }
    }, _callee7, undefined);
  }));

  return function encryptBuffer(_x19, _x20, _x21) {
    return _ref7.apply(this, arguments);
  };
}();

/**
 * Encrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 * @returns {Object} - The stringified ciphertext object (ciphertext and iv)
 */
var encrypt = function () {
  var _ref8 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee8(key, data) {
    var format = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'hex';
    var context, cipherContext, encrypted;
    return _regenerator2.default.wrap(function _callee8$(_context8) {
      while (1) {
        switch (_context8.prev = _context8.next) {
          case 0:
            _checkCryptokey(key);
            context = {
              iv: genRandomBuffer(16),
              plaintext: Buffer.from(JSON.stringify(data))

              // Prepare cipher context, depends on cipher mode
            };
            cipherContext = {
              name: key.algorithm.name,
              iv: context.iv
            };
            _context8.next = 5;
            return encryptBuffer(key, context.plaintext, cipherContext);

          case 5:
            encrypted = _context8.sent;
            return _context8.abrupt('return', {
              ciphertext: Buffer.from(encrypted).toString(format),
              iv: Buffer.from(context.iv).toString(format)
            });

          case 7:
          case 'end':
            return _context8.stop();
        }
      }
    }, _callee8, undefined);
  }));

  return function encrypt(_x23, _x24) {
    return _ref8.apply(this, arguments);
  };
}();

/**
 * Decrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 */
var decrypt = function () {
  var _ref9 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee9(key, ciphertext) {
    var format = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'hex';
    var context, cipherContext, decrypted;
    return _regenerator2.default.wrap(function _callee9$(_context9) {
      while (1) {
        switch (_context9.prev = _context9.next) {
          case 0:
            _checkCryptokey(key);
            context = {
              ciphertext: ciphertext.hasOwnProperty('ciphertext') ? Buffer.from(ciphertext.ciphertext, format) : '',
              // IV is 128 bits long === 16 bytes
              iv: ciphertext.hasOwnProperty('iv') ? Buffer.from(ciphertext.iv, format) : ''
              // Prepare cipher context, depends on cipher mode
            };
            cipherContext = {
              name: key.algorithm.name,
              iv: context.iv
            };
            _context9.next = 5;
            return decryptBuffer(key, context.ciphertext, cipherContext);

          case 5:
            decrypted = _context9.sent;
            return _context9.abrupt('return', JSON.parse(Buffer.from(decrypted).toString()));

          case 7:
          case 'end':
            return _context9.stop();
        }
      }
    }, _callee9, undefined);
  }));

  return function decrypt(_x26, _x27) {
    return _ref9.apply(this, arguments);
  };
}();

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
  importKey: importKey,
  exportKey: exportKey,
  genAESKey: genAESKey,
  genRandomBuffer: genRandomBuffer,
  getBuffer: getBuffer,
  checkPassphrase: checkPassphrase,
  derivePassphrase: derivePassphrase
};