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
  })
})
