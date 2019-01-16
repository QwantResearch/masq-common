/* eslint-env mocha */
/* global MasqCommon */
/* global chai */

describe('MasqCommon utils', () => {
  // track created databases to be able to delete them after each tests
  let dbNames = []
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
      const db = await MasqCommon.utils.createPromisifiedHyperDB('dB2')
      await MasqCommon.utils.dbReady(db)
      await MasqCommon.utils.put(db, masterKey, 'one', item)
      const dec = await MasqCommon.utils.get(db, masterKey, 'one')
      chai.assert.deepEqual(dec, item)
      // check stored value, must contains iv and ciphertext properties
      const enc = (await db.getAsync('one')).value
      chai.assert.exists(enc.iv)
      chai.assert.exists(enc.ciphertext)
    })

    it('Should list (export) keys/values or return {} if empty', async () => {
      const masterKey = await MasqCommon.crypto.genAESKey()
      const prefix = ('/')
      const item = { one: '1' }
      const item2 = { two: '2' }
      const db = await MasqCommon.utils.createPromisifiedHyperDB('dB3')
      await MasqCommon.utils.dbReady(db)
      const emptyList = await MasqCommon.utils.list(db, masterKey)
      chai.assert.lengthOf(Object.keys(emptyList), 0)
      const emptyListWithPrefix = await MasqCommon.utils.list(db, masterKey, prefix)
      chai.assert.lengthOf(Object.keys(emptyListWithPrefix), 0)

      await MasqCommon.utils.put(db, masterKey, 'one', item)
      await MasqCommon.utils.put(db, masterKey, 'two', item2)
      const list = await MasqCommon.utils.list(db, masterKey)
      chai.assert.lengthOf(Object.keys(list), 2)
      const listWithPrefix = await MasqCommon.utils.list(db, masterKey, prefix)
      chai.assert.lengthOf(Object.keys(listWithPrefix), 2)
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
        const db = await MasqCommon.utils.createPromisifiedHyperDB('dB5')
        await MasqCommon.utils.list(db)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NO_ENCRYPTION_KEY, 'Reject if no encryption key  is given')
    })
  })
})
