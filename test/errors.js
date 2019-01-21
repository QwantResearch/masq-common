/* eslint-env mocha */
/* global MasqCommon */
/* global chai */

describe('MasqCommon errors', () => {
  context('CheckObject', () => {
    it('Should not throw ', async () => {
      const myObj = { name: 'Bob', age: 18 }
      const requiredParameters = ['age', 'name']
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        MasqCommon.errors.checkObject(myObj, requiredParameters)
      } catch (error) {
        err.type = '_ERROR_THROWN'
      }
      chai.assert.equal(err.type, '_ERROR_NOT_THROWN_', 'Should not reject')
    })
    it('Should not throw if a property has an empty string', async () => {
      const myObj = { name: '', age: 18 }
      const requiredParameters = ['age', 'name']
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        MasqCommon.errors.checkObject(myObj, requiredParameters)
      } catch (error) {
        err.type = '_ERROR_THROWN'
      }
      chai.assert.equal(err.type, '_ERROR_NOT_THROWN_', 'Should not reject')
    })
    it('Should not throw if a property has an object', async () => {
      const myObj = { name: { id: 'id' }, age: 18 }
      const requiredParameters = ['age', 'name']
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        MasqCommon.errors.checkObject(myObj, requiredParameters)
      } catch (error) {
        err.type = '_ERROR_THROWN'
      }
      chai.assert.equal(err.type, '_ERROR_NOT_THROWN_', 'Should not reject')
    })
    it('Should throw if any property is not set ', async () => {
      const myObj = { age: 18 }
      const requiredParameters = ['age', 'name']
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        MasqCommon.errors.checkObject(myObj, requiredParameters)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.WRONG_PARAMETER, 'Should not reject')
    })

    it('Should throw if any property is undefined ', async () => {
      const myObj = { name: undefined, age: 18 }
      const requiredParameters = ['age', 'name']
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        MasqCommon.errors.checkObject(myObj, requiredParameters)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.WRONG_PARAMETER, 'Should not reject')
    })
  })
})
