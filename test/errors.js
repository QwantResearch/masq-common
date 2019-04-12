/* eslint-env mocha */
/* global MasqCommon */
/* global chai */
const { WRONG_PARAMETER } = MasqCommon.errors.MasqError
const { checkObject } = MasqCommon.errors
const requiredParameters = ['age', 'name']

describe('MasqCommon errors', () => {
  context('CheckObject', () => {
    it('Should not throw ', async () => {
      const myObj = { name: 'Bob', age: 18 }
      const toCall = () => checkObject(myObj, requiredParameters)
      chai.expect(toCall).to.not.throw()
    })
    it('Should not throw if a property has an empty string', async () => {
      const myObj = { name: '', age: 18 }
      const toCall = () => checkObject(myObj, requiredParameters)
      chai.expect(toCall).to.not.throw()
    })
    it('Should not throw if a property has an object', async () => {
      const myObj = { name: { id: 'id' }, age: 18 }
      const toCall = () => checkObject(myObj, requiredParameters)
      chai.expect(toCall).to.not.throw()
    })
    it('Should not throw if a property is null', async () => {
      const myObj = { name: null, age: 18 }
      const toCall = () => checkObject(myObj, requiredParameters)
      chai.expect(toCall).to.not.throw()
    })
    it('Should throw if any property is not set ', async () => {
      const myObj = { age: 18 }
      const toCall = () => checkObject(myObj, requiredParameters)
      chai.expect(toCall).to.throw().with.property('code', WRONG_PARAMETER)
    })
    it('Should throw if any property is undefined ', async () => {
      const myObj = { name: undefined, age: 18 }
      const toCall = () => checkObject(myObj, requiredParameters)
      chai.expect(toCall).to.throw().with.property('code', WRONG_PARAMETER)
    })
  })
})
