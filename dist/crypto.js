'use strict';

var _errors = require('./errors');

var genRandomBuffer = function genRandomBuffer() {
  var len = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 16;

  var values = window.crypto.getRandomValues(new Uint8Array(len));
  return Buffer.from(values);
};

/**
 *  Return a buffer of an UInt8Array
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

var requiredParameterHashedPassphrase = ['salt', 'iterations', 'storedHash', 'hashAlgo'];

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
var hash256 = function hash256(msg) {
  var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'SHA-256';

  return window.crypto.subtle.digest({
    name: 'SHA-256'
  }, typeof msg === 'string' ? Buffer.from(msg) : msg).then(function (digest) {
    return new Uint8Array(digest);
  });
};

/**
 * Derive a passphrase and return the object to store
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @returns {Promise<HashedPassphrase>}   A promise that contains the derived key
 */
var derivePassphrase = function derivePassphrase(passPhrase, salt) {
  _checkPassphrase(passPhrase);
  var _salt = salt || genRandomBuffer(16);
  var iterations = 100000;
  return deriveBitsAndHash(passPhrase, _salt, iterations).then(function (hashedValue) {
    return {
      salt: Buffer.from(_salt).toString('hex'),
      iterations: iterations,
      hashAlgo: 'SHA-256',
      storedHash: Buffer.from(hashedValue).toString('hex')
    };
  }).catch(function (err) {
    return console.err(err);
  });
};

/**
 * Derive the passphrase with PBKDF2 and hash the output with the given hash function
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hash] The hash function used for derivation and final hash computing
 * @returns {Promise<Uint8Array>}   A promise that contains the hashed derived key
 */
var deriveBitsAndHash = function deriveBitsAndHash(passPhrase, salt, iterations, hash) {
  return deriveBits(passPhrase, salt, iterations, hash).then(hash256);
};

/**
 * Check a given passphrase by comparing it to the stored hash value (in HashedPassphrase object)
 *
 * @param {string} passphrase The passphrase
 * @param {HashedPassphrase} hashedPassphrase The HashedPassphrase object
 * @returns {Promise<Boolean>}   A promise
 */
var checkPassphrase = function checkPassphrase(passPhrase, hashedPassphrase) {
  _checkPassphrase(passPhrase);
  (0, _errors.checkObject)(hashedPassphrase, requiredParameterHashedPassphrase);
  var salt = hashedPassphrase.salt,
      iterations = hashedPassphrase.iterations,
      storedHash = hashedPassphrase.storedHash,
      hashAlgo = hashedPassphrase.hashAlgo;

  return deriveBitsAndHash(passPhrase, Buffer.from(salt, 'hex'), iterations, hashAlgo).then(function (hashedValue) {
    return Buffer.from(hashedValue).toString('hex') === storedHash;
  });
};

/**
   * Generate an AES key based on the cipher mode and keysize
   * @param {boolean} [extractable] - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {CryptoKey} - The generated AES key.
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
var exportKey = function exportKey(key) {
  var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';

  return window.crypto.subtle.exportKey(type, key).then(function (key) {
    if (type === 'raw') return new Uint8Array(key);
    return key;
  });
};

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
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {ArrayBuffer} key - The AES key as raw data. 128 or 256 bits
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only AES-GCM)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The decrypted buffer
 */
var decryptBuffer = function decryptBuffer(data, key, cipherContext) {
  // TODO: test input params
  return window.crypto.subtle.decrypt(cipherContext, key, data).then(function (result) {
    return new Uint8Array(result);
  });
};

/**
 * Encrypt buffer
 *
 * @param {ArrayBuffer} data - Data to encrypt
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only AES-GCM)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The encrypted buffer
 */
var encryptBuffer = function encryptBuffer(data, key, cipherContext) {
  return window.crypto.subtle.encrypt(cipherContext, key, data).then(function (result) {
    return new Uint8Array(result);
  });
};

/**
 * Encrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 * @returns {Object} - The stringified ciphertext object (ciphertext and iv)
 */
var encrypt = function encrypt(key, data) {
  var format = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'hex';

  _checkCryptokey(key);
  var context = {
    iv: genRandomBuffer(16),
    plaintext: Buffer.from(JSON.stringify(data))

    // Prepare cipher context, depends on cipher mode
  };var cipherContext = {
    name: key.algorithm.name,
    iv: context.iv
  };
  return encryptBuffer(context.plaintext, key, cipherContext).then(function (result) {
    return {
      ciphertext: Buffer.from(result).toString(format),
      iv: Buffer.from(context.iv).toString(format)
    };
  });
};

/**
 * Decrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 */
var decrypt = function decrypt(key, ciphertext) {
  var format = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'hex';

  _checkCryptokey(key);
  var context = {
    ciphertext: ciphertext.hasOwnProperty('ciphertext') ? Buffer.from(ciphertext.ciphertext, format) : '',
    // IV is 128 bits long === 16 bytes
    iv: ciphertext.hasOwnProperty('iv') ? Buffer.from(ciphertext.iv, format) : ''
    // Prepare cipher context, depends on cipher mode
  };var cipherContext = {
    name: key.algorithm.name,
    iv: context.iv
  };

  return decryptBuffer(context.ciphertext, key, cipherContext).then(function (res) {
    return JSON.parse(Buffer.from(res).toString());
  });
};

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