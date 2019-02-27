/* eslint-env mocha */
/* global MasqCommon */
/* global chai */
/* eslint no-undef: "off" */

const { utils } = MasqCommon

describe('MasqCommon utils', () => {
  // track created databases to be able to delete them after each tests
  let dbNames = []
  const nonce = '7692c3ad3540bb803c020b3aee66'
  const nonce2 = '7692c3ad3540bb803c020b3aaaaa'
  let originalCreate = utils.createPromisifiedHyperDB
  utils.createPromisifiedHyperDB = (...args) => {
    dbNames.push(args[0])
    return originalCreate(...args)
  }

  afterEach(() => {
    dbNames.forEach(db => { window.indexedDB.deleteDatabase(db) })
    dbNames = []
  })

  context('IndexedDB operations', () => {
    it('DB should exist', async () => {
      window.indexedDB.open('test1')
      const exists = await utils.dbExists('test1')
      chai.assert.equal(exists, true, 'database must exist')
      window.indexedDB.deleteDatabase('test1')
    })

    it('DB should not exist', async () => {
      const exists = await utils.dbExists('test2')
      chai.assert.equal(exists, false, 'database must not exist')
    })

    it('Should hash each subpaths of a given key', async () => {
      const key = '/favoris/paris'
      const prefixes = await utils.hashKey(key, nonce)
      const expected = 'ab595ffb49ed89da9e15a501d65f2fe0d0c47ef41ff346c2cd31246dd5c54003/e13e07a3ac6a83421551448b2ba94205a0fdaca27d622addc8bab44300f28290'
      chai.assert.deepEqual(prefixes, expected)
    })

    it('Should hash each subpaths of a given key with another nonce', async () => {
      const key = '/favoris/paris'
      const prefixes = await utils.hashKey(key, nonce2)
      const expected = 'c58137d4f5a672b183b457663c5ab0355b5918def3ba70792155642a2b34daf0/efc0f9d738122cda257ac816d5ce52903539e1b416eee9735e1b66aa25259fb9'
      chai.assert.deepEqual(prefixes, expected)
    })

    it('Should create an hyperDB instance and put/get a value', async () => {
      const item = { un: '1' }
      const db = await utils.createPromisifiedHyperDB('dB1')
      await utils.dbReady(db)
      await db.putAsync('hello', item)
      const res = (await db.getAsync('hello')).value
      chai.assert.deepEqual(res, item)
    })
    it('Should put/get encrypted values in the db', async () => {
      const masterKey = await crypto.genAESKey()
      const item = { one: '1' }
      const keyName = 'one'
      const db = await utils.createPromisifiedHyperDB('dB2')
      await utils.dbReady(db)
      await utils.put(db, masterKey, nonce, keyName, item)
      const dec = await utils.get(db, masterKey, nonce, keyName)
      chai.assert.deepEqual(dec, item)
      // check stored value, must contains iv and ciphertext properties
      const hashedKeyName = await utils.hashKey(keyName, nonce)
      const enc = (await db.getAsync(hashedKeyName)).value
      chai.assert.exists(enc.iv)
      chai.assert.exists(enc.ciphertext)
    })

    it('Should list (export) keys/values or return {} if empty', async () => {
      const masterKey = await crypto.genAESKey()
      const prefix = ('/fav/')
      const item = { one: '1' }
      const item2 = { two: '2' }
      const db = await utils.createPromisifiedHyperDB('dB3')
      await utils.dbReady(db)
      const emptyList = await utils.list(db, masterKey, nonce)
      chai.assert.lengthOf(Object.keys(emptyList), 0)

      const emptyListWithPrefix = await utils.list(db, masterKey, nonce, prefix)
      chai.assert.lengthOf(Object.keys(emptyListWithPrefix), 0)

      await utils.put(db, masterKey, nonce, `${prefix}one`, item)
      await utils.put(db, masterKey, nonce, `${prefix}two`, item2)
      const list = await utils.list(db, masterKey, nonce)

      chai.assert.lengthOf(Object.keys(list), 2)
      const listWithPrefix = await utils.list(db, masterKey, nonce, prefix)
      chai.assert.lengthOf(Object.keys(listWithPrefix), 2)
    })

    it('Should list (export) keys/values for a prefix with / or not at the beginning/end', async () => {
      const masterKey = await crypto.genAESKey()
      const prefix1 = ('/fav/')
      const prefix2 = ('/fav')
      const prefix3 = ('fav')
      const prefix4 = ('/fav//')
      const item = { one: '1' }
      const expected = { 'fav/one': { one: '1' } }
      const db = await utils.createPromisifiedHyperDB('dB9')
      await utils.dbReady(db)
      await utils.put(db, masterKey, nonce, `${prefix1}one`, item)
      const list1 = await utils.list(db, masterKey, nonce, prefix1)
      chai.assert.deepEqual(list1, expected)
      const list2 = await utils.list(db, masterKey, nonce, prefix2)
      chai.assert.deepEqual(list2, expected)
      const list3 = await utils.list(db, masterKey, nonce, prefix3)
      chai.assert.deepEqual(list3, expected)
      const list4 = await utils.list(db, masterKey, nonce, prefix4)
      chai.assert.deepEqual(list4, expected)
    })

    it('Should list (export) keys/values, the keys first and last / if exists must be removed', async () => {
      const masterKey = await crypto.genAESKey()
      const prefix = ('/players/')
      const player1 = { name: 'bob' }
      const player2 = { name: 'tom' }
      const db = await utils.createPromisifiedHyperDB('dB10')
      await utils.dbReady(db)
      await utils.put(db, masterKey, nonce, `${prefix}1`, player1)
      await utils.put(db, masterKey, nonce, `${prefix}2`, player2)
      const list = await utils.list(db, masterKey, nonce, prefix)
      const expected = { 'players/2': { name: 'tom' }, 'players/1': { name: 'bob' } }
      chai.assert.deepEqual(list, expected)
    })

    it('Should reject if a db is not given to put', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await utils.put()
      } catch (error) {
        err = error
      }

      chai.assert.equal(err.type, ERRORS.NO_DB, 'Reject if no db is given') // eslint no-unused-vars
    })
    it('Should reject if an encryption key is not given to put', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const db = await utils.createPromisifiedHyperDB('dB5')
        await utils.put(db)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.NO_ENCRYPTION_KEY, 'Reject if no encryption key  is given')
    })
    it('Should reject if an nonce is not given to put', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const db = await utils.createPromisifiedHyperDB('dB5')
        await utils.put(db, 'secretKey')
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.NO_NONCE, 'Reject if no nonce key  is given')
    })
    it('Should reject if a db is not given to get/ or is not an hyperDB instance', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await utils.get()
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.NO_DB, 'Reject if no db is given')
    })
    it('Should reject if an encryption key is not given to get', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const db = await utils.createPromisifiedHyperDB('dB6')
        await utils.get(db)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.NO_ENCRYPTION_KEY, 'Reject if no encryption key  is given')
    })
    it('Should reject if a nonce is not given to get', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const db = await utils.createPromisifiedHyperDB('dB7')
        await utils.get(db, 'secretKey')
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.NO_NONCE, 'Reject if no nonce  is given')
    })
    it('Should reject if a db is not given to list', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await utils.list()
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.NO_DB, 'Reject if no db is given')
    })
    it('Should reject if an encryption key is not given to list', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const db = await utils.createPromisifiedHyperDB('dB8')
        await utils.list(db)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NO_ENCRYPTION_KEY, 'Reject if no encryption key  is given')
    })
  })
})
