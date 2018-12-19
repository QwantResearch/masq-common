const promisifyAll = require('bluebird').promisifyAll
const hyperdb = require('hyperdb')
const rai = require('random-access-idb')

module.exports = {
  dbReady,
  dbExists,
  createPromisifiedHyperDB,
  getHashParams
}

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
