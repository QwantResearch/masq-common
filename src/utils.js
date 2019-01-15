import { encrypt, decrypt } from './crypto'
import { ERRORS, MasqError } from './errors'
const promisifyAll = require('bluebird').promisifyAll
const hyperdb = require('hyperdb')
const rai = require('random-access-idb')

function createPromisifiedHyperDB (name, hexKey) {
  const keyBuffer = hexKey
    ? Buffer.from(hexKey, 'hex')
    : null
  return promisifyAll(hyperdb(rai(name), keyBuffer, { valueEncoding: 'json', firstNode: true }))
}

function dbReady (db) {
  return new Promise((resolve, reject) => {
    db.on('ready', () => {
      resolve()
    })
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

function getHashParams (link) {
  const url = new URL(link)
  const hash = url.hash.slice(2)
  const hashParamsArr = JSON.parse(Buffer.from(hash, 'base64').toString('utf8'))
  if (!Array.isArray(hashParamsArr) || hashParamsArr.length !== 4) {
    throw new Error('Wrong login URL')
  }
  const hashParamsObj = {
    appName: hashParamsArr[0],
    requestType: hashParamsArr[1],
    channel: hashParamsArr[2],
    key: hashParamsArr[3]
  }
  hashParamsObj.key = Buffer.from(hashParamsObj.key, 'base64')
  return hashParamsObj
}

/**
   * Get a value
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} key - The key name
   * @returns {Promise}
   */
const get = async (db, encKey, key) => {
  if (!(db instanceof hyperdb)) throw new MasqError(ERRORS.NO_DB)
  if (!encKey) throw new MasqError(ERRORS.NO_ENCRYPTION_KEY)
  const node = await db.getAsync(key)
  if (!node) return null
  const dec = await decrypt(encKey, node.value)
  return dec
}

/**
   * Put a new value in the db
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} key - The key name
   * @param {any} value - The value to insert
   * @returns {Promise}
   */
const put = async (db, encKey, key, value) => {
  if (!(db instanceof hyperdb)) throw new MasqError(ERRORS.NO_DB)
  if (!encKey) throw new MasqError(ERRORS.NO_ENCRYPTION_KEY)
  const enc = await encrypt(encKey, value)
  return db.putAsync(key, enc)
}

/**
   * List all keys and values
   * @param {Object} db - The hyperDB instance
   * @param {CryptoKey} enckey - The enc/dec AES key
   * @param {string} prefix - Prefix
   * @returns {Promise}
   */
const list = async (db, encKey, prefix) => {
  if (!(db instanceof hyperdb)) throw new MasqError(ERRORS.NO_DB)
  if (!encKey) throw new MasqError(ERRORS.NO_ENCRYPTION_KEY)

  const list = await db.listAsync(prefix)
  if (list.length === 1 && list[0].key === '' && list[0].value === null) {
    return {}
  }

  const decList = await Promise.all(list.map(async (elt) => ({
    key: elt.key,
    value: await decrypt(encKey, elt.value)
  })))

  const reformattedDic = decList.reduce((dic, e) => {
    const el = Array.isArray(e) ? e[0] : e
    dic[el.key] = el.value
    return dic
  }, {})
  return reformattedDic
}

module.exports = {
  dbReady,
  dbExists,
  createPromisifiedHyperDB,
  getHashParams,
  get,
  put,
  list
}
