import { ERRORS, checkObject, MasqError } from './errors'

const _checkEncodingFormat = (format) => {
  if (format !== 'hex' && format !== 'base64') throw new MasqError(ERRORS.INVALID_ENCODING_FORMAT)
}

const genRandomBuffer = (len = 16) => {
  const values = window.crypto.getRandomValues(new Uint8Array(len))
  return Buffer.from(values)
}

const genRandomBufferAsStr = (len = 16, encodingFormat = 'hex') => {
  if (encodingFormat) {
    _checkEncodingFormat(encodingFormat)
  }
  const buf = genRandomBuffer(len)
  return buf.toString(encodingFormat)
}

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
const getBuffer = (arr) => {
  return Buffer.from(arr)
}

/**
 @typedef protectedMasterKeyAndNonce
 @type {Object}
 @property {derivationParams} derivationParams - The derivation params.
 @property {encryptedMasterKeyAndNonce} encryptedMasterKeyAndNonce - The encrypted masterKey and nonce
 */

/**
 @typedef derivationParams
 @type {Object}
 @property {string} hashAlgo - The hash algo for the PBKDF2 and the final hash to store it
 @property {sring} salt - The salt used to derive the key (format: hex string)
 @property {Number} iterations - The iteration # used during key derivation
 */

/**
 @typedef keyEncryptionKey
 @type {Object}
 @property {Object} derivationParams - The derivation parmaeters
 @property {Cryptokey} key - The key encryption key (used to protect the MasterKey)
 */

/**
 @typedef masterKeyAndNonce
 @type {Object}
 @property {string} masterKey - The master key (hex format)
 @property {string} nonce - The nonce used to protect the keys in hyperdb
 */

/**
 @typedef encryptedMasterKeyAndNonce
 @type {Object}
 @property {string} iv - The iv used to encrypt the masterKey (format: hex string)
 @property {string} ciphertext - The encrypted masterKey (format: hex string)
 */

const _checkPassphrase = (passphrase) => {
  if (typeof passphrase !== 'string' || passphrase === '') {
    throw new MasqError(ERRORS.INVALID_PASSPHRASE)
  }
}

const _checkCryptokey = (key) => {
  if (!key.type || key.type !== 'secret') {
    throw new MasqError(ERRORS.INVALID_CRYPTOKEY)
  }
}

/**
 * Generate a PBKDF2 derived key (bits) based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation
 * @returns {Promise<Uint8Array>}   A promise that contains the derived key
 */
const deriveBits = async (passPhrase, salt, iterations, hashAlgo) => {
  // Always specify a strong salt
  if (iterations < 10000) { console.warn('The iteration number is less than 10000, increase it !') }

  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    (typeof passPhrase === 'string') ? Buffer.from(passPhrase) : passPhrase,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  )
  const derivedKey = await window.crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: salt || new Uint8Array([]),
    iterations: iterations || 100000,
    hash: hashAlgo || 'SHA-256'
  }, baseKey, 128)

  return new Uint8Array(derivedKey)
}

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} msg The message
 * @param {string} [encodingFormat] The encoding format ('hex' by default, could be 'base64')
 * @returns {Promise<String>}   A promise that contains the hash as a String encoded with encodingFormat
 */
const hash256 = (msg, encodingFormat) => {
  if (encodingFormat) {
    _checkEncodingFormat(encodingFormat)
  }
  return hashMsg(msg, encodingFormat || 'hex', 'SHA-256')
}

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} msg The message
 * @param {string} [encodingFormat] The encoding format ('hex' by default, could be 'base64')
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise<String>}  A promise that contains the hash as a String encoded with encodingFormat
 */
const hashMsg = async (msg, encodingFormat, type = 'SHA-256') => {
  const digest = await window.crypto.subtle.digest(
    {
      name: type
    },
    (typeof msg === 'string') ? Buffer.from(msg) : msg
  )
  return Buffer.from(digest).toString(encodingFormat)
}

/**
 * Derive a key based on a given passphrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<keyEncryptionKey>}   A promise that contains the derived key and derivation parameters
 */
const deriveKeyFromPassphrase = async (passPhrase, salt, iterations, hashAlgo) => {
  _checkPassphrase(passPhrase)
  const _hashAlgo = hashAlgo || 'SHA-256'
  const _salt = salt || genRandomBuffer(16)
  const _iterations = iterations || 100000

  const derivedKey = await deriveBits(passPhrase, _salt, _iterations, _hashAlgo)
  const key = await importKey(derivedKey)
  return {
    derivationParams: {
      salt: Buffer.from(_salt).toString('hex'),
      iterations: _iterations,
      hashAlgo: _hashAlgo
    },
    key
  }
}

/**
 * Derive the passphrase with PBKDF2 to obtain a KEK
 * Generate a AES key (masterKey)
 * Encrypt the masterKey with the KEK
 * Generate a nonce and encrypt it also with the KEK
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hashAlgo] The hash function used for derivation and final hash computing
 * @returns {Promise<protectedMasterKeyAndNonce>}   A promise that contains the hashed derived key
 */
const genEncryptedMasterKeyAndNonce = async (passPhrase, salt, iterations, hashAlgo) => {
  // derive key encryption key from passphrase
  const keyEncryptionKey = await deriveKeyFromPassphrase(passPhrase, salt, iterations, hashAlgo)

  // Generate the masterKey
  const masterKey = await genRandomBufferAsStr(16, 'hex')
  const nonce = await genRandomBufferAsStr(16, 'hex')
  const toBeEncryptedMasterKeyAndNonce = {
    masterKey,
    nonce
  }

  const encryptedMasterKeyAndNonce = await encrypt(keyEncryptionKey.key, toBeEncryptedMasterKeyAndNonce)

  return {
    derivationParams: keyEncryptionKey.derivationParams,
    encryptedMasterKeyAndNonce
  }
}

const requiredParameterProtectedMasterKeyAndNonce = ['encryptedMasterKeyAndNonce', 'derivationParams']

/**
 * Derive a given key by deriving
 * the encryption key from a
 * given passphrase and derivation params.
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {protectedMasterKeyAndNonce} protectedMasterKeyAndNonce - The same object returned by genEncryptedMasterKey
 * @returns {Promise<masterKeyAndNonce>}   A promise that contains the masterKey and the nonce
 */
const decryptMasterKeyAndNonce = async (passPhrase, protectedMasterKeyAndNonce) => {
  checkObject(protectedMasterKeyAndNonce, requiredParameterProtectedMasterKeyAndNonce)
  const { derivationParams, encryptedMasterKeyAndNonce } = protectedMasterKeyAndNonce
  const { salt, iterations, hashAlgo } = derivationParams
  const _salt = typeof (salt) === 'string' ? Buffer.from(salt, ('hex')) : salt
  try {
    const derivedKey = await deriveBits(passPhrase, _salt, iterations, hashAlgo)
    const keyEncryptionKey = await importKey(derivedKey)
    const encryptedMasterKeyAndNonceHex = await decrypt(keyEncryptionKey, encryptedMasterKeyAndNonce)
    return {
      masterKey: Buffer.from(encryptedMasterKeyAndNonceHex.masterKey, 'hex'),
      nonce: encryptedMasterKeyAndNonceHex.nonce
    }
  } catch (error) {
    throw new MasqError(ERRORS.WRONG_PASSPHRASE)
  }
}

/**
 * Update the KEK based on the new passphrase from user
 * Note: the MK and the nonce must not be changed!
 *
 * @param {string | arrayBuffer} currentPassPhrase The current (old) passphrase that is used to derive the key
 * @param {string | arrayBuffer} newPassPhrase The new passphrase that will be used to derive the key
 * @param {protectedMasterKeyAndNonce} protectedMasterKeyAndNonce - The same object returned by genEncryptedMasterKey for the old passphrase
 * @returns {Promise<protectedMasterKeyAndNonce>}  
 */
const updateMasterKeyAndNonce = async (currentPassPhrase, newPassPhrase, protectedMasterKeyAndNonce) => {
  const { masterKey, nonce } = await decryptMasterKeyAndNonce(currentPassPhrase, protectedMasterKeyAndNonce)
  // derive a new key encryption key from newPassPhrase
  const keyEncryptionKey = await deriveKeyFromPassphrase(newPassPhrase)

  // Use existing masterKey and nonce
  // Because masterKey is a buffer, we encode it as a hex string.
  // The nonce is already as a hex string
  const toBeEncryptedMasterKeyAndNonce = {
    masterKey: masterKey.toString('hex'),
    nonce
  }

  const encryptedMasterKeyAndNonce = await encrypt(keyEncryptionKey.key, toBeEncryptedMasterKeyAndNonce)

  return {
    derivationParams: keyEncryptionKey.derivationParams,
    encryptedMasterKeyAndNonce
  }
}

/**
   * Generate an AES key based on the cipher mode and keysize
   * @param {boolean} [extractable] - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {Promise<CryptoKey>} - The generated AES key.
   */
const genAESKey = (extractable, mode, keySize) => {
  return window.crypto.subtle.generateKey({
    name: mode || 'AES-GCM',
    length: keySize || 128
  }, extractable || true, ['decrypt', 'encrypt'])
}

/**
  * Export a CryptoKey into a raw|jwk key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @param {string} [type] - The type of the exported key
  * @returns {Promise<arrayBuffer>} - The raw key or the key as a jwk format
  */
const exportKey = async (key, type = 'raw') => {
  const exportedKey = await window.crypto.subtle.exportKey(type, key)
  if (type === 'raw') return new Uint8Array(exportedKey)
  return exportedKey
}

/**
  * Import a raw|jwk as a CryptoKey
  *
  * @param {arrayBuffer|Object} key - The key
  * @param {string} [type] - The type of the key to import ('raw', 'jwk')
  * @param {string} [mode] - The mode of the key to import (default 'AES-GCM')
  * @returns {Promise<arrayBuffer>} - The cryptoKey
  */
const importKey = (key, type = 'raw', mode = 'AES-GCM') => {
  return window.crypto.subtle.importKey(type, key, { name: mode }
    , true, ['encrypt', 'decrypt'])
}

/**
 * Decrypt buffer
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only AES-GCM)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {Promise<ArrayBuffer>} - The decrypted buffer
 */
const decryptBuffer = async (key, data, cipherContext) => {
  // TODO: test input params
  try {
    const decrypted = await window.crypto.subtle.decrypt(cipherContext, key, data)
    return new Uint8Array(decrypted)
  } catch (e) {
    if (e.message === 'Unsupported state or unable to authenticate data') {
      throw new MasqError(ERRORS.UNABLE_TO_DECRYPT)
    }
  }
}

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
const encryptBuffer = async (key, data, cipherContext) => {
  const encrypted = await window.crypto.subtle.encrypt(cipherContext, key, data)
  return new Uint8Array(encrypted)
}

/**
 * Encrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 * @returns {Object} - The stringified ciphertext object (ciphertext and iv)
 */
const encrypt = async (key, data, format = 'hex') => {
  _checkCryptokey(key)
  let context = {
    iv: genRandomBuffer(key.algorithm.name === 'AES-GCM' ? 12 : 16),
    plaintext: Buffer.from(JSON.stringify(data))
  }

  // Prepare cipher context, depends on cipher mode
  let cipherContext = {
    name: key.algorithm.name,
    iv: context.iv
  }

  const encrypted = await encryptBuffer(key, context.plaintext, cipherContext)
  return {
    ciphertext: Buffer.from(encrypted).toString(format),
    iv: Buffer.from(context.iv).toString(format)
  }
}

/**
 * Decrypt data
 *
 * @param {CryptoKey} key - The AES CryptoKey
 * @param {string | Object} - The data to encrypt
 * @param {string} [format] - The ciphertext and iv encoding format
 */
const decrypt = async (key, ciphertext, format = 'hex') => {
  _checkCryptokey(key)

  let context = {
    ciphertext: ciphertext.hasOwnProperty('ciphertext') ? Buffer.from(ciphertext.ciphertext, (format)) : '',
    // IV is 128 bits long === 16 bytes
    iv: ciphertext.hasOwnProperty('iv') ? Buffer.from(ciphertext.iv, (format)) : ''
  }

  // Prepare cipher context, depends on cipher mode
  let cipherContext = {
    name: key.algorithm.name,
    iv: context.iv
  }
  try {
    const decrypted = await decryptBuffer(key, context.ciphertext, cipherContext)
    return JSON.parse(Buffer.from(decrypted).toString())
  } catch (error) {
    throw new MasqError(ERRORS.UNABLE_TO_DECRYPT)
  }
}

export {
  encrypt,
  decrypt,
  importKey,
  exportKey,
  genAESKey,
  genRandomBuffer,
  genRandomBufferAsStr,
  getBuffer,
  decryptMasterKeyAndNonce,
  genEncryptedMasterKeyAndNonce,
  updateMasterKeyAndNonce,
  hash256
}
