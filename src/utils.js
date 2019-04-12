import { encrypt, decrypt, hash256 } from './crypto'
import { MasqError } from './errors'
import { promisify } from 'es6-promisify'
const hyperdb = require('hyperdb')
const rai = require('random-access-idb')

function createPromisifiedHyperDB (name, hexKey) {
  const methodsToPromisify = ['version', 'put', 'get', 'del', 'batch', 'list', 'authorize', 'authorized']
  const keyBuffer = hexKey
    ? Buffer.from(hexKey, 'hex')
    : null

  const db = hyperdb(rai(name), keyBuffer, { valueEncoding: 'json', firstNode: true })

  // Promisify methods with Async suffix
  methodsToPromisify.forEach(m => {
    db[`${m}Async`] = promisify(db[m])
  })

  return db
}

function dbReady (db) {
  return new Promise((resolve) => {
    db.ready(resolve)
  })
}

function dbExists (dbName) {
  return new Promise((resolve, reject) => {
    const req = window.indexedDB.open(dbName)
    let existed = true
    req.onsuccess = () => {
      req.result.close()
      if (!existed) { window.indexedDB.deleteDatabase(dbName) }
      resolve(existed)
    }
    req.onupgradeneeded = () => {
      existed = false
    }
    req.onerror = (err) => {
      reject(err)
    }
  })
}

/**
 *
 * @param {string} key - The key (/prefix/key)
 * @param {string} nonce - The nonce is used to ensure privacy and avoid de-anonymization (hex string)
 */
const hashKey = async (key, nonce) => {
  if (key === '/' || key === '') return '/'
  const prefixes = key.split('/').filter(prefix => prefix !== '')
  const hashedPrefixes = await Promise.all(prefixes.map(async (prefix) => hash256(`${nonce}${prefix}`)))
  return hashedPrefixes.join('/')
}

/**
   * Get a value
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} key - The key name
   * @param {string} nonce - The nonce as hex string
   * @returns {Promise}
   */
const get = async (db, encKey, nonce, key) => {
  if (key === undefined || key === null) return null
  if (!db) throw new MasqError(MasqError.NO_DB)
  if (!encKey) throw new MasqError(MasqError.NO_ENCRYPTION_KEY)
  if (!nonce) throw new MasqError(MasqError.NO_NONCE)
  const hashedKey = await hashKey(key, nonce)

  const node = await db.getAsync(hashedKey)
  if (!node) return null
  const dec = await decrypt(encKey, node.value)
  // dec contains an object with key and value
  return dec.value
}

/**
   * Put a new value in the db
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} nonce - The nonce as hex string
   * @param {string} key - The key name
   * @param {any} value - The value to insert
   * @returns {Promise}
   */
const put = async (db, encKey, nonce, key, value) => {
  if (key === undefined || key === null) return null
  if (!db) throw new MasqError(MasqError.NO_DB)
  if (!encKey) throw new MasqError(MasqError.NO_ENCRYPTION_KEY)
  if (!nonce) throw new MasqError(MasqError.NO_NONCE)

  let sanitizedKey = key

  if (sanitizedKey[0] === '/') {
    sanitizedKey = sanitizedKey.slice(1)
  }

  if (sanitizedKey[sanitizedKey.length - 1] === '/') {
    sanitizedKey = sanitizedKey.slice(0, -1)
  }

  const withKeyName = {
    key: sanitizedKey,
    value: value
  }
  const enc = await encrypt(encKey, withKeyName)
  const hashedKey = await hashKey(key, nonce)

  return db.putAsync(hashedKey, enc)
}

/**
   * Delete a key/value
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} nonce - The nonce as hex string
   * @param {string} key - The key name
   * @returns {Promise}
   */
const del = async (db, encKey, nonce, key) => {
  if (key === undefined || key === null) return null
  if (!db) throw new MasqError(MasqError.NO_DB)
  if (!encKey) throw new MasqError(MasqError.NO_ENCRYPTION_KEY)
  if (!nonce) throw new MasqError(MasqError.NO_NONCE)

  const hashedKey = await hashKey(key, nonce)
  return db.delAsync(hashedKey)
}

/**
   * List all keys and values
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} nonce - The nonce as hex string
   * @param {string} [prefix] - Prefix
   * @returns {Promise}
   */
const list = async (db, encKey, nonce, prefix) => {
  if (prefix === null) return null
  if (!db) throw new MasqError(MasqError.NO_DB)
  if (!encKey) throw new MasqError(MasqError.NO_ENCRYPTION_KEY)
  if (!nonce) throw new MasqError(MasqError.NO_NONCE)

  const _prefix = prefix ? await hashKey(prefix, nonce) : '/'
  const list = await db.listAsync(_prefix)
  if (list.length === 1 && list[0].key === '' && list[0].value === null) {
    return {}
  }
  const decList = await Promise.all(list.map((elt) => {
    const dec = decrypt(encKey, elt.value)
    return dec
  }))

  const reformattedDic = decList.reduce((dic, e) => {
    dic[e.key] = e.value
    return dic
  }, {})

  return reformattedDic
}

/**
   * Set a watcher
   * @param {Object} db - The hyperDB instance
   * @param {string} nonce - The nonce as hex string
   * @param {string} key - Key
   * @param {Object} cb
   * @returns {Object}
   */
const watch = async (db, nonce, key, cb) => {
  const hashedKey = await hashKey(key, nonce)
  return db.watch(hashedKey, cb)
}

export {
  watch,
  dbReady,
  dbExists,
  createPromisifiedHyperDB,
  get,
  put,
  del,
  list,
  hashKey
}
