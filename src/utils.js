import { generateError, ERRORS, checkObject } from './errors'

const genRandomBuffer = (len = 16) => {
  return window.crypto.getRandomValues(new Uint8Array(len))
}

/**
 @typedef HashedPassphrase
 @type {Object}
 @property {string} storedHash - The hash of the derived key (format: hex string)
 @property {string} hashAlgo - The hash algo for the PBKDF2 and the final hash to store it
 @property {sring} salt - The salt used to derive the key (format: hex string)
 @property {Number} iterations - The iteration # used during key derivation
 */

const requiredParameterHashedPassphrase = ['salt', 'iterations', 'storedHash', 'hashAlgo']

const _checkPassphrase = (passphrase) => {
  if (typeof passphrase !== 'string' || passphrase === '') {
    throw generateError(ERRORS.NOPASSPHRASE)
  }
}

const _checkCryptokey = (key) => {
  if (key.type !== 'secret') {
    throw generateError(ERRORS.NOCRYPTOKEY)
  }
}

/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hash] The hash function used for derivation
 * @returns {Promise<Uint8Array>}   A promise that contains the derived key
 */
const deriveBits = (passPhrase, salt, iterations, hash) => {
  // Always specify a strong salt
  if (iterations < 10000) { console.warn('The iteration number is less than 10000, increase it !') }

  return window.crypto.subtle.importKey(
    'raw',
    (typeof passPhrase === 'string') ? Buffer.from(passPhrase) : passPhrase,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  )
    .then(baseKey => {
      return window.crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: salt || new Uint8Array([]),
        iterations: iterations || 100000,
        hash: hash || 'SHA-256'
      }, baseKey, 128)
    })
    .then(derivedKey => new Uint8Array(derivedKey))
}

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} msg The message
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise<Uint8Array>}   A promise that contains the hash as a Uint8Array
 */
const hash256 = (msg, type = 'SHA-256') => {
  return window.crypto.subtle.digest(
    {
      name: 'SHA-256'
    },
    (typeof msg === 'string') ? Buffer.from(msg) : msg
  )
    .then(digest => new Uint8Array(digest))
}

/**
 * Derive a passphrase and return the object to store
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @returns {Promise<HashedPassphrase>}   A promise that contains the derived key
 */
const derivePassphrase = (passPhrase) => {
  _checkPassphrase(passPhrase)
  let hashedPassphrase = {}
  const salt = window.crypto.getRandomValues(new Uint8Array(16))
  const iterations = 100000
  hashedPassphrase.salt = Buffer.from(salt).toString('hex')
  hashedPassphrase.iterations = iterations
  hashedPassphrase.hashAlgo = 'SHA-256'
  return deriveBitsAndHash(passPhrase, salt, iterations)
    .then(hashedValue => {
      hashedPassphrase.storedHash = Buffer.from(hashedValue).toString('hex')
      return hashedPassphrase
    })
    .catch(err => console.log(err)
    )
}

/**
 * Derive the passphrase with PBKDF2 and hash the output with the given hash function
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hash] The hash function used for derivation and final hash computing
 * @returns {Promise<Uint8Array>}   A promise that contains the hashed derived key
 */
const deriveBitsAndHash = (passPhrase, salt, iterations, hash) => {
  return deriveBits(passPhrase, salt, iterations, hash)
    .then(hash256)
}

/**
 * Check a given passphrase by comparing it to the stored hash value (in HashedPassphrase object)
 *
 * @param {string} passphrase The passphrase
 * @param {HashedPassphrase} hashedPassphrase The HashedPassphrase object
 * @returns {Promise<Boolean>}   A promise
 */
const checkPassphrase = (passPhrase, hashedPassphrase) => {
  _checkPassphrase(passPhrase)
  checkObject(hashedPassphrase, requiredParameterHashedPassphrase)
  const { salt, iterations, storedHash, hashAlgo } = hashedPassphrase
  return deriveBitsAndHash(passPhrase, Buffer.from(salt, 'hex'), iterations, hashAlgo)
    .then(hashedValue => {
      return Buffer.from(hashedValue).toString('hex') === storedHash
    })
}

/**
   * Generate an AES key based on the cipher mode and keysize
   * @param {boolean} [extractable] - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {CryptoKey} - The generated AES key.
   */
const genAESKey = (extractable, mode, keySize) => {
  return window.crypto.subtle.generateKey({
    name: mode || 'aes-gcm',
    length: keySize || 128
  }, extractable || true, ['decrypt', 'encrypt'])
}

/**
  * Export a CryptoKey into a raw|jwk key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @param {string} [type] - The type of the exported key
  * @returns {arrayBuffer|Object} - The raw key or the key as a jwk format
  */
const exportKey = (key, type = 'raw') => {
  return window.crypto.subtle.exportKey(type, key)
    .then(key => {
      if (type === 'raw') return new Uint8Array(key)
      return key
    })
}

/**
  * Import a raw|jwk as a CryptoKey
  *
  * @param {arrayBuffer|Object} key - The key
  * @param {string} [type] - The type of the key to import ('raw', 'jwk')
  * @param {string} [mode] - The mode of the key to import (default 'AES-GCM')
  * @returns {arrayBuffer|Object} - The cryptoKey
  */
const importKey = (key, type = 'raw', mode = 'AES-GCM') => {
  return window.crypto.subtle.importKey(type, key, { name: mode }
    , true, ['encrypt', 'decrypt'])
}

/**
 * Decrypt buffer
 *
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {ArrayBuffer} key - The AES key as raw data. 128 or 256 bits
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only aes-gcm)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The decrypted buffer
 */
const decryptBuffer = (data, key, cipherContext) => {
  // TODO: test input params
  return window.crypto.subtle.decrypt(cipherContext, key, data)
    .then(result => new Uint8Array(result))
}

/**
 * Encrypt buffer
 *
 * @param {ArrayBuffer} data - Data to encrypt
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only aes-gcm)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The encrypted buffer
 */
const encryptBuffer = (data, key, cipherContext) => {
  return window.crypto.subtle.encrypt(cipherContext, key, data)
    .then(result => new Uint8Array(result))
}

/**
 * Encrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 * @returns {Object} - The stringified ciphertext object (ciphertext and iv)
 */
const encrypt = (key, data, format = 'hex') => {
  _checkCryptokey(key)
  let context = {}
  let cipherContext = {}
  context.iv = genRandomBuffer(16)
  context.plaintext = Buffer.from(JSON.stringify(data))

  // Prepare cipher context, depends on cipher mode
  cipherContext.name = key.algorithm.name
  cipherContext.iv = context.iv
  return encryptBuffer(context.plaintext, key, cipherContext)
    .then(result => {
      return {
        ciphertext: Buffer.from(result).toString(format),
        iv: Buffer.from(context.iv).toString(format)
      }
    })
}

/**
 * Decrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 */
const decrypt = (key, ciphertext, format = 'hex') => {
  _checkCryptokey(key)
  let context = {}
  let cipherContext = {}
  context.ciphertext = ciphertext.hasOwnProperty('ciphertext') ? Buffer.from(ciphertext.ciphertext, (format)) : ''
  // IV is 128 bits long === 16 bytes
  context.iv = ciphertext.hasOwnProperty('iv') ? Buffer.from(ciphertext.iv, (format)) : ''
  // Prepare cipher context, depends on cipher mode
  cipherContext.name = key.algorithm.name
  cipherContext.iv = context.iv
  return decryptBuffer(context.ciphertext, key, cipherContext)
    .then(res => JSON.parse(Buffer.from(res).toString()))
}

module.exports = { encrypt, decrypt, importKey, exportKey, genAESKey, genRandomBuffer, checkPassphrase, derivePassphrase }
