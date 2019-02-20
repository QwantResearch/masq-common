import { encrypt, decrypt, hash256 } from './crypto'
import { ERRORS, MasqError } from './errors'
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
  const prefixes = key.split('/').filter(prefix => prefix !== '')
  // console.log(prefixes)
  const hashedPrefixes = await Promise.all(prefixes.map(async (prefix) => hash256(`${nonce}${prefix}`)))
  // console.log(hashedPrefixes)
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
const get = async (db, encKey, key, nonce) => {
  if (!db) throw new MasqError(ERRORS.NO_DB)
  if (!encKey) throw new MasqError(ERRORS.NO_ENCRYPTION_KEY)
  const hashedKey = await hashKey(key, nonce)
  // console.log('get', key, hashedKey)

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
   * @param {string} key - The key name
   * @param {any} value - The value to insert
   * @param {string} nonce - The nonce as hex string
   * @returns {Promise}
   */
const put = async (db, encKey, key, value, nonce) => {
  if (!db) throw new MasqError(ERRORS.NO_DB)
  if (!encKey) throw new MasqError(ERRORS.NO_ENCRYPTION_KEY)
  const withKeyName = {
    key: key,
    value: value
  }
  const enc = await encrypt(encKey, withKeyName)
  const hashedKey = await hashKey(key, nonce)
  // console.log('put', key, hashedKey)

  return db.putAsync(hashedKey, enc)
}

/**
   * List all keys and values
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} prefix - Prefix
   * @returns {Promise}
   */
const list = async (db, encKey, prefix) => {
  if (!db) throw new MasqError(ERRORS.NO_DB)
  if (!encKey) throw new MasqError(ERRORS.NO_ENCRYPTION_KEY)

  const _prefix = prefix ? hashKey(prefix) : '/'
  const list = await db.listAsync(_prefix)
  if (list.length === 1 && list[0].key === '' && list[0].value === null) {
    return {}
  }
  const decList = await Promise.all(list.map(async (elt) => {
    const dec = await decrypt(encKey, elt.value)
    return {
      key: dec.key,
      value: dec.value
    }
  }))

  const reformattedDic = decList.reduce((dic, e) => {
    dic[e.key] = e.value
    return dic
  }, {})

  return reformattedDic
}

export {
  dbReady,
  dbExists,
  createPromisifiedHyperDB,
  get,
  put,
  list,
  hashKey
}
