/* eslint-env mocha */
/* global MasqCommon */
/* global chai */

describe('MasqCommon utils', () => {
  context('IndexedDB operations', () => {
    it('DB should exist', async () => {
      window.indexedDB.open('test1')
      const exists = await MasqCommon.utils.dbExists('test1')
      chai.assert.equal(exists, true, 'database must exist')
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
      const item = { un: '1' }
      const db = await MasqCommon.utils.createPromisifiedHyperDB('dB2')
      await MasqCommon.utils.dbReady(db)
      await MasqCommon.utils.put(db, masterKey, 'hello', item)
      const dec = await MasqCommon.utils.get(db, masterKey, 'hello')
      chai.assert.deepEqual(dec, item)
      // check stored value, must contains iv and ciphertext properties
      db.get('hello', (err, node) => {
        if (err) throw err
        const enc = node.value
        chai.assert.exists(enc.iv)
        chai.assert.exists(enc.ciphertext)
      })
    })
    it('Should reject if a db is not given to put', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.utils.put()
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NODB, 'Reject if no db is given')
    })
    it('Should reject if an encryption key is not given to put', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.utils.put({})
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NOENCRYPTIONKEY, 'Reject if no encryption  is given')
    })
    it('Should reject if a db is not given to get', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.utils.get()
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NODB, 'Reject if no db is given')
    })
    it('Should reject if an encryption key is not given to get', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.utils.get({})
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NOENCRYPTIONKEY, 'Reject if no encryption  is given')
    })
  })
})
