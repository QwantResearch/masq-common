/* eslint-env mocha */
/* global MasqCommon */
/* global chai */

describe('MasqCommon utils', () => {
  // track created databases to be able to delete them after each tests
  let dbNames = []
  const nonce = '7692c3ad3540bb803c020b3aee66'
  let originalCreate = MasqCommon.utils.createPromisifiedHyperDB
  MasqCommon.utils.createPromisifiedHyperDB = (...args) => {
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
      const exists = await MasqCommon.utils.dbExists('test1')
      chai.assert.equal(exists, true, 'database must exist')
      window.indexedDB.deleteDatabase('test1')
    })

    it('DB should not exist', async () => {
      const exists = await MasqCommon.utils.dbExists('test2')
      chai.assert.equal(exists, false, 'database must not exist')
    })

    it('Should hash each subpaths of a given key', async () => {
      const key = '/favoris/paris'
      const prefixes = await MasqCommon.utils.hashKey(key)
      const expected = '55b29c9511f2460c96cb2e17695be711f5fc2052f560aa6dbe06d274de682701/24ecca2efd35a52dbb7705852e23e4b0760897c454eb620bbe66b6a5e8116297'
      chai.assert.deepEqual(prefixes, expected)
    })

    it('Should create an hyperDB instance and put/get a value', async () => {
      const item = { un: '1' }
      const db = await MasqCommon.utils.createPromisifiedHyperDB('dB1')
      await MasqCommon.utils.dbReady(db)
      await db.putAsync('hello', item)
      const res = (await db.getAsync('hello')).value
      chai.assert.deepEqual(res, item)
    })
    it('Should put/get encrypted values in the db', async () => {
      const masterKey = await MasqCommon.crypto.genAESKey()
      const item = { one: '1' }
      const keyName = 'one'
      // needed to check if encryption is ok
      // const hashedKeyName = '7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed'
      const db = await MasqCommon.utils.createPromisifiedHyperDB('dB2')
      await MasqCommon.utils.dbReady(db)
      await MasqCommon.utils.put(db, masterKey, keyName, item, nonce)
      const dec = await MasqCommon.utils.get(db, masterKey, keyName, nonce)
      chai.assert.deepEqual(dec, item)
      // check stored value, must contains iv and ciphertext properties
      const hashedKeyName = await MasqCommon.utils.hashKey(keyName, nonce)
      const enc = (await db.getAsync(hashedKeyName)).value
      chai.assert.exists(enc.iv)
      chai.assert.exists(enc.ciphertext)
    })

    it('Should list (export) keys/values or return {} if empty', async () => {
      const masterKey = await MasqCommon.crypto.genAESKey()
      const prefix = ('/fav/')
      const item = { one: '1' }
      const item2 = { two: '2' }
      const db = await MasqCommon.utils.createPromisifiedHyperDB('dB3')
      await MasqCommon.utils.dbReady(db)
      const emptyList = await MasqCommon.utils.list(db, masterKey)
      chai.assert.lengthOf(Object.keys(emptyList), 0)

      const emptyListWithPrefix = await MasqCommon.utils.list(db, masterKey, prefix)
      chai.assert.lengthOf(Object.keys(emptyListWithPrefix), 0)

      await MasqCommon.utils.put(db, masterKey, `${prefix}one`, item, nonce)
      await MasqCommon.utils.put(db, masterKey, `${prefix}two`, item2, nonce)
      const list = await MasqCommon.utils.list(db, masterKey)

      chai.assert.lengthOf(Object.keys(list), 2)
      const listWithPrefix = await MasqCommon.utils.list(db, masterKey, prefix)
      chai.assert.lengthOf(Object.keys(listWithPrefix), 2)
    })

    it('Should list (export) keys/values for a prefix with / or not at the beginning/end', async () => {
      const masterKey = await MasqCommon.crypto.genAESKey()
      const prefix1 = ('/fav/')
      const prefix2 = ('/fav')
      const prefix3 = ('fav')
      const item = { one: '1' }
      const db = await MasqCommon.utils.createPromisifiedHyperDB('dB9')
      await MasqCommon.utils.dbReady(db)

      await MasqCommon.utils.put(db, masterKey, `${prefix1}one`, item)
      const list1 = await MasqCommon.utils.list(db, masterKey, prefix1)
      chai.assert.lengthOf(Object.keys(list1), 1)
      const list2 = await MasqCommon.utils.list(db, masterKey, prefix2)
      chai.assert.lengthOf(Object.keys(list2), 1)
      const list3 = await MasqCommon.utils.list(db, masterKey, prefix3)
      chai.assert.lengthOf(Object.keys(list3), 1)
    })

    it('Should reject if a db is not given to put', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.utils.put()
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NO_DB, 'Reject if no db is given')
    })
    it('Should reject if an encryption key is not given to put', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const db = await MasqCommon.utils.createPromisifiedHyperDB('dB5')
        await MasqCommon.utils.put(db)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NO_ENCRYPTION_KEY, 'Reject if no encryption key  is given')
    })
    it('Should reject if a db is not given to get/ or is not an hyperDB instance', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.utils.get()
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NO_DB, 'Reject if no db is given')
    })
    it('Should reject if an encryption key is not given to get', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const db = await MasqCommon.utils.createPromisifiedHyperDB('dB5')
        await MasqCommon.utils.get(db)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NO_ENCRYPTION_KEY, 'Reject if no encryption key  is given')
    })
    it('Should reject if a db is not given to list', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.utils.list()
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NO_DB, 'Reject if no db is given')
    })
    it('Should reject if an encryption key is not given to list', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const db = await MasqCommon.utils.createPromisifiedHyperDB('dB6')
        await MasqCommon.utils.list(db)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NO_ENCRYPTION_KEY, 'Reject if no encryption key  is given')
    })
  })
})
