import { ERRORS, checkObject, MasqError } from './errors'

const genRandomBuffer = (len = 16) => {
  const values = window.crypto.getRandomValues(new Uint8Array(len))
  return Buffer.from(values)
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
 @typedef protectedMasterKey
 @type {Object}
 @property {derivationParams} derivationParams - The derivation params.
 @property {encryptedMasterKey} encryptedMasterKey - The encrypted masterKey
 */

/**
 @typedef derivationParams
 @type {Object}
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
 @typedef encryptedMasterKey
 @type {Object}
 @property {string} iv - The iv used to encrypt the masterKey (format: hex string)
 @property {string} ciphertext - The encrypted masterKey (format: hex string)
 */

const _checkPassphrase = (passphrase) => {
  if (typeof passphrase !== 'string' || passphrase === '') {
    throw new MasqError(ERRORS.NOPASSPHRASE)
  }
}

const _checkCryptokey = (key) => {
  if (!key.type || key.type !== 'secret') {
    throw new MasqError(ERRORS.NOCRYPTOKEY)
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
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise<Uint8Array>}   A promise that contains the hash as a Uint8Array
 */
const hash256 = async (msg, type = 'SHA-256') => {
  const digest = await window.crypto.subtle.digest(
    {
      name: 'SHA-256'
    },
    (typeof msg === 'string') ? Buffer.from(msg) : msg
  )
  return new Uint8Array(digest)
}

/**
 * Derive a passphrase and return the object to store
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @returns {Promise<HashedPassphrase>}   A promise that contains the derived key
 */
const deriveKeyFromPassphrase = async (passPhrase, salt) => {
  _checkPassphrase(passPhrase)
  const hashAlgo = 'SHA-256'
  const _salt = salt || genRandomBuffer(16)
  const iterations = 100000

  const derivedKey = await deriveBits(passPhrase, _salt, iterations, hashAlgo)
  const key = await importKey(derivedKey)
  // const encMasterKey = await deriveBitsGenAndencMasterKey(passPhrase, _salt, iterations, hashAlgo)
  return {
    derivationParams: {
      salt: Buffer.from(_salt).toString('hex'),
      iterations: iterations,
      hashAlgo
    },
    key
  }
}

/**
 * Derive the passphrase with PBKDF2
 * Generate a AES key (masterKey)
 * Encrypt the masterKey
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hash] The hash function used for derivation and final hash computing
 * @returns {Promise<Uint8Array>}   A promise that contains the hashed derived key
 */
const genEncryptedMasterKey = async (passPhrase, salt, iterations, hash) => {
  // derive key encryption key from passphrase
  const keyEncryptionKey = await deriveKeyFromPassphrase(passPhrase, salt)

  // Generate the masterKey
  const masterKey = await genRandomBuffer(16)
  const encryptedMasterKey = await encrypt(keyEncryptionKey.key, Buffer.from(masterKey).toString('hex'))
  return {
    derivationParams: keyEncryptionKey.derivationParams,
    encryptedMasterKey
  }
}
const requiredParameterProtectedMasterKey = ['encryptedMasterKey', 'derivationParams']

/**
 * Derive a given key by deriving
 * the encryption key from a
 * given passphrase and derivation params.
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {protectedMasterKey} protectedMasterKey - The same object returned by genEncryptedMasterKey
 * @returns {Promise<Uint8Array>}   A promise that contains the masterKey
 */
const decryptMasterKey = async (passPhrase, protectedMasterKey) => {
  checkObject(protectedMasterKey, requiredParameterProtectedMasterKey)
  const { derivationParams, encryptedMasterKey } = protectedMasterKey
  const { salt, iterations, hashAlgo } = derivationParams
  const _salt = typeof (salt) === 'string' ? Buffer.from(salt, ('hex')) : salt
  try {
    const derivedKey = await deriveBits(passPhrase, _salt, iterations, hashAlgo)
    const keyEncryptionKey = await importKey(derivedKey)
    const masterKeyHex = await decrypt(keyEncryptionKey, encryptedMasterKey)
    return Buffer.from(masterKeyHex, 'hex')
  } catch (error) {
    throw new MasqError(ERRORS.WRONGPASSPHRASE)
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

  const decrypted = await decryptBuffer(key, context.ciphertext, cipherContext)
  return JSON.parse(Buffer.from(decrypted).toString())
}

module.exports = {
  encrypt,
  decrypt,
  importKey,
  exportKey,
  genAESKey,
  genRandomBuffer,
  getBuffer,
  decryptMasterKey,
  genEncryptedMasterKey
}
