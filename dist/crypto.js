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
 @typedef protectedMasterKey
 @type {Object}
 @property {encMasterKey} encMasterKey - The encrypted MasterKey
 @property {string} hashAlgo - The hash algo for the PBKDF2 and the final hash to store it
 @property {sring} salt - The salt used to derive the key (format: hex string)
 @property {Number} iterations - The iteration # used during key derivation
 */

/**
 @typedef HashedPassphrase
 @type {Object}
 @property {string} storedHash - The hash of the derived key (format: hex string)
 @property {string} hashAlgo - The hash algo for the PBKDF2 and the final hash to store it
 @property {sring} salt - The salt used to derive the key (format: hex string)
 @property {Number} iterations - The iteration # used during key derivation
 */

/**
 @typedef encMasterKey
 @type {Object}
 @property {string} iv - The iv used to encrypt the masterKey (format: hex string)
 @property {string} ciphertext - The encrypted masterKey (format: hex string)
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
 * Generate a PBKDF2 derived key (bits) based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation
 * @returns {Promise<Uint8Array>}   A promise that contains the derived key
 */
var deriveBits = function () {
  var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(passPhrase, salt, iterations, hashAlgo) {
    var baseKey, derivedKey;
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            // Always specify a strong salt
            if (iterations < 10000) {
              console.warn('The iteration number is less than 10000, increase it !');
            }

            _context.next = 3;
            return window.crypto.subtle.importKey('raw', typeof passPhrase === 'string' ? Buffer.from(passPhrase) : passPhrase, 'PBKDF2', false, ['deriveBits', 'deriveKey']);

          case 3:
            baseKey = _context.sent;
            _context.next = 6;
            return window.crypto.subtle.deriveBits({
              name: 'PBKDF2',
              salt: salt || new Uint8Array([]),
              iterations: iterations || 100000,
              hash: hashAlgo || 'SHA-256'
            }, baseKey, 128);

          case 6:
            derivedKey = _context.sent;
            return _context.abrupt('return', new Uint8Array(derivedKey));

          case 8:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, undefined);
  }));

  return function deriveBits(_x2, _x3, _x4, _x5) {
    return _ref.apply(this, arguments);
  };
}();

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} msg The message
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise<Uint8Array>}   A promise that contains the hash as a Uint8Array
 */
var hash256 = function () {
  var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(msg) {
    var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'SHA-256';
    var digest;
    return _regenerator2.default.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            _context2.next = 2;
            return window.crypto.subtle.digest({
              name: 'SHA-256'
            }, typeof msg === 'string' ? Buffer.from(msg) : msg);

          case 2:
            digest = _context2.sent;
            return _context2.abrupt('return', new Uint8Array(digest));

          case 4:
          case 'end':
            return _context2.stop();
        }
      }
    }, _callee2, undefined);
  }));

  return function hash256(_x7) {
    return _ref2.apply(this, arguments);
  };
}();

/**
 * Derive a passphrase and return the object to store
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @returns {Promise<HashedPassphrase>}   A promise that contains the derived key
 */
var deriveKeyFromPassphrase = function () {
  var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(passPhrase, salt) {
    var hashAlgo, _salt, iterations, derivedKey, key;

    return _regenerator2.default.wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            _checkPassphrase(passPhrase);
            hashAlgo = 'SHA-256';
            _salt = salt || genRandomBuffer(16);
            iterations = 100000;
            // Derive a key from the passphrase

            _context3.next = 6;
            return deriveBits(passPhrase, _salt, iterations, hashAlgo);

          case 6:
            derivedKey = _context3.sent;

            console.log('derivedKey in gen', derivedKey);
            console.log('derivedKey in gen passphrase', passPhrase);
            console.log('derivedKey in gen _salt', _salt);
            console.log('derivedKey in gen options ', {
              salt: Buffer.from(_salt).toString('hex'),
              iterations: iterations,
              hashAlgo: hashAlgo
            });
            _context3.next = 13;
            return importKey(derivedKey);

          case 13:
            key = _context3.sent;
            return _context3.abrupt('return', {
              derivationParams: {
                salt: Buffer.from(_salt).toString('hex'),
                iterations: iterations,
                hashAlgo: hashAlgo
              },
              key: key
            });

          case 15:
          case 'end':
            return _context3.stop();
        }
      }
    }, _callee3, undefined);
  }));

  return function deriveKeyFromPassphrase(_x8, _x9) {
    return _ref3.apply(this, arguments);
  };
}();

var requiredParameterEncMasterKey = ['derivationParams', 'key'];
var requiredParameterDerivationParams = ['salt', 'iterations', 'hashAlgo'];

var genEncryptedMasterKey = function () {
  var _ref4 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee4(passphrase, salt) {
    var keyEncryptionKey, masterKey, encMasterKey;
    return _regenerator2.default.wrap(function _callee4$(_context4) {
      while (1) {
        switch (_context4.prev = _context4.next) {
          case 0:
            _context4.next = 2;
            return deriveKeyFromPassphrase(passphrase, salt);

          case 2:
            keyEncryptionKey = _context4.sent;


            // Generate the master key
            masterKey = genRandomBuffer(16);

            // Encrypt the Master Key with the keyEncryptionKey

            _context4.next = 6;
            return encrypt(keyEncryptionKey.key, Buffer.from(masterKey).toString('hex'));

          case 6:
            encMasterKey = _context4.sent;
            return _context4.abrupt('return', {
              derivationParams: keyEncryptionKey.derivationParams,
              key: encMasterKey
            });

          case 8:
          case 'end':
            return _context4.stop();
        }
      }
    }, _callee4, undefined);
  }));

  return function genEncryptedMasterKey(_x10, _x11) {
    return _ref4.apply(this, arguments);
  };
}();

/**
 * Decrypt a given key by deriving the key encryption key from the a given passphrase and derivation params
 *
 * @param {string} passphrase The passphrase
 * @param {encMasterKey} protectedMasterKey The protectedMasterKey object
 * @returns {Promise<Boolean>}   A promise
 */
var decryptMasterKey = function () {
  var _ref5 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee5(passPhrase, encMasterKey) {
    var _encMasterKey$derivat, salt, iterations, hashAlgo, _salt, derivedKey, derivedKeyEncryptionKey, masterKey;

    return _regenerator2.default.wrap(function _callee5$(_context5) {
      while (1) {
        switch (_context5.prev = _context5.next) {
          case 0:
            _checkPassphrase(passPhrase);
            (0, _errors.checkObject)(encMasterKey, requiredParameterEncMasterKey);
            (0, _errors.checkObject)(encMasterKey.derivationParams, requiredParameterDerivationParams);
            _context5.prev = 3;
            _encMasterKey$derivat = encMasterKey.derivationParams, salt = _encMasterKey$derivat.salt, iterations = _encMasterKey$derivat.iterations, hashAlgo = _encMasterKey$derivat.hashAlgo;
            // init salt

            _salt = typeof salt === 'string' ? Buffer.from(salt, 'hex') : salt;
            // derive key from passphrase

            _context5.next = 8;
            return deriveBits(passPhrase, _salt, iterations, hashAlgo);

          case 8:
            derivedKey = _context5.sent;

            console.log('derivedKey', derivedKey);
            console.log('derivedKey passphrase', passPhrase);
            console.log('derivedKey _salt', _salt);
            console.log('derivedKey options ', encMasterKey.derivationParams);
            _context5.next = 15;
            return importKey(derivedKey);

          case 15:
            derivedKeyEncryptionKey = _context5.sent;

            // decrypt encrypted master key with the key derived from the passphrase
            console.log('encMasterKey', encMasterKey);

            _context5.next = 19;
            return decrypt(derivedKeyEncryptionKey, encMasterKey.key);

          case 19:
            masterKey = _context5.sent;
            return _context5.abrupt('return', Buffer.from(masterKey, 'hex'));

          case 23:
            _context5.prev = 23;
            _context5.t0 = _context5['catch'](3);
            throw new Error('Wrong Passphrase');

          case 26:
          case 'end':
            return _context5.stop();
        }
      }
    }, _callee5, undefined, [[3, 23]]);
  }));

  return function decryptMasterKey(_x12, _x13) {
    return _ref5.apply(this, arguments);
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
  * @returns {Promise<arrayBuffer>} - The raw key or the key as a jwk format
  */
var exportKey = function () {
  var _ref6 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee6(key) {
    var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';
    var exportedKey;
    return _regenerator2.default.wrap(function _callee6$(_context6) {
      while (1) {
        switch (_context6.prev = _context6.next) {
          case 0:
            _context6.next = 2;
            return window.crypto.subtle.exportKey(type, key);

          case 2:
            exportedKey = _context6.sent;

            if (!(type === 'raw')) {
              _context6.next = 5;
              break;
            }

            return _context6.abrupt('return', new Uint8Array(exportedKey));

          case 5:
            return _context6.abrupt('return', exportedKey);

          case 6:
          case 'end':
            return _context6.stop();
        }
      }
    }, _callee6, undefined);
  }));

  return function exportKey(_x15) {
    return _ref6.apply(this, arguments);
  };
}();

/**
  * Import a raw|jwk as a CryptoKey
  *
  * @param {arrayBuffer|Object} key - The key
  * @param {string} [type] - The type of the key to import ('raw', 'jwk')
  * @param {string} [mode] - The mode of the key to import (default 'AES-GCM')
  * @returns {Promise<arrayBuffer>} - The cryptoKey
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
 * @returns {Promise<ArrayBuffer>} - The decrypted buffer
 */
var decryptBuffer = function () {
  var _ref7 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee7(key, data, cipherContext) {
    var decrypted;
    return _regenerator2.default.wrap(function _callee7$(_context7) {
      while (1) {
        switch (_context7.prev = _context7.next) {
          case 0:
            _context7.next = 2;
            return window.crypto.subtle.decrypt(cipherContext, key, data);

          case 2:
            decrypted = _context7.sent;
            return _context7.abrupt('return', new Uint8Array(decrypted));

          case 4:
          case 'end':
            return _context7.stop();
        }
      }
    }, _callee7, undefined);
  }));

  return function decryptBuffer(_x18, _x19, _x20) {
    return _ref7.apply(this, arguments);
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
  var _ref8 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee8(key, data, cipherContext) {
    var encrypted;
    return _regenerator2.default.wrap(function _callee8$(_context8) {
      while (1) {
        switch (_context8.prev = _context8.next) {
          case 0:
            _context8.next = 2;
            return window.crypto.subtle.encrypt(cipherContext, key, data);

          case 2:
            encrypted = _context8.sent;
            return _context8.abrupt('return', new Uint8Array(encrypted));

          case 4:
          case 'end':
            return _context8.stop();
        }
      }
    }, _callee8, undefined);
  }));

  return function encryptBuffer(_x21, _x22, _x23) {
    return _ref8.apply(this, arguments);
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
  var _ref9 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee9(key, data) {
    var format = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'hex';
    var context, cipherContext, encrypted;
    return _regenerator2.default.wrap(function _callee9$(_context9) {
      while (1) {
        switch (_context9.prev = _context9.next) {
          case 0:
            _checkCryptokey(key);
            context = {
              iv: genRandomBuffer(key.algorithm.name === 'AES-GCM' ? 12 : 16),
              plaintext: Buffer.from(JSON.stringify(data))

              // Prepare cipher context, depends on cipher mode
            };
            cipherContext = {
              name: key.algorithm.name,
              iv: context.iv
            };
            _context9.next = 5;
            return encryptBuffer(key, context.plaintext, cipherContext);

          case 5:
            encrypted = _context9.sent;
            return _context9.abrupt('return', {
              ciphertext: Buffer.from(encrypted).toString(format),
              iv: Buffer.from(context.iv).toString(format)
            });

          case 7:
          case 'end':
            return _context9.stop();
        }
      }
    }, _callee9, undefined);
  }));

  return function encrypt(_x25, _x26) {
    return _ref9.apply(this, arguments);
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
  var _ref10 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee10(key, ciphertext) {
    var format = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'hex';
    var context, cipherContext, decrypted;
    return _regenerator2.default.wrap(function _callee10$(_context10) {
      while (1) {
        switch (_context10.prev = _context10.next) {
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
            _context10.next = 5;
            return decryptBuffer(key, context.ciphertext, cipherContext);

          case 5:
            decrypted = _context10.sent;
            return _context10.abrupt('return', JSON.parse(Buffer.from(decrypted).toString()));

          case 7:
          case 'end':
            return _context10.stop();
        }
      }
    }, _callee10, undefined);
  }));

  return function decrypt(_x28, _x29) {
    return _ref10.apply(this, arguments);
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
  genEncryptedMasterKey: genEncryptedMasterKey,
  decryptMasterKey: decryptMasterKey
};