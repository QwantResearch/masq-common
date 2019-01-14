/* eslint-env mocha */
/* global MasqCommon */
/* global chai */

describe('MasqCommon crypto', function () {
  context('Generating a random buffer (e.g. iv)', () => {
    it('Should generate a random buffer without length parameter', () => {
      const iv1 = MasqCommon.crypto.genRandomBuffer()
      chai.assert.lengthOf(iv1, 16, 'Default length is 16')
    })

    it('Should generate a random buffer with a specific length parameter', () => {
      const iv2 = MasqCommon.crypto.genRandomBuffer(8)
      chai.assert.lengthOf(iv2, 8, 'Array length is not 8')
    })
  })

  context('Should derive and hash a passphrase ', () => {
    let passphrase = 'mySecretPass'

    it('Should derive a passphrase [string] with default settings', async () => {
      const hashedPassphrase = await MasqCommon.crypto.derivePassphrase(passphrase)
      chai.assert.equal(hashedPassphrase.hashAlgo, 'SHA-256', 'Default hash algo is SHA-256')
      chai.assert.equal(hashedPassphrase.iterations, 100000, 'Default iteration is 100000')
      chai.assert.lengthOf(hashedPassphrase.storedHash, 64, 'SHA-256 returns a 256 bits array, 64 bytes as hex string')
      chai.assert.lengthOf(hashedPassphrase.salt, 32, 'Default salt is 128 bits array, 32 bytes as hex string')
    })

    it('Should reject if passphrase is not a string or is empty', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.crypto.derivePassphrase([])
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NOPASSPHRASE, 'Reject if passphrase is not a string')
    })

    it('Should return true if the given passphrase is the same as the stored one', async () => {
      const hashedPassphrase = await MasqCommon.crypto.derivePassphrase(passphrase)
      const res = await MasqCommon.crypto.checkPassphrase(passphrase, hashedPassphrase)
      chai.assert.isTrue(res, 'The check operation should return true')
    })

    it('Should return false if the given passphrase is NOT the same as the stored one', async () => {
      const hashedPassphrase = await MasqCommon.crypto.derivePassphrase(passphrase)
      const res = await MasqCommon.crypto.checkPassphrase(passphrase + 'modifed', hashedPassphrase)
      chai.assert.isFalse(res, 'The check operation should return false')
    })

    it('Should reject if the any property of hashedPassphrase is missing or empty', async () => {
      let err = '_ERROR_NOT_THROWN_'
      try {
        await MasqCommon.crypto.checkPassphrase('secretPassphraseCandidate', {})
      } catch (error) {
        err = error.name
      }
      chai.assert.equal(err, MasqCommon.errors.ERRORS.WRONGPARAMETER, 'A requried property is missing')
    })

    it('The salt and storedHash must be different for two consecutive call to derivePassphrase even with the same passphrase', async () => {
      const passphrase = 'secret'
      const hashedPassphrase1 = await MasqCommon.crypto.derivePassphrase(passphrase)
      const hashedPassphrase2 = await MasqCommon.crypto.derivePassphrase(passphrase)
      chai.assert.equal(hashedPassphrase1.salt === hashedPassphrase2.salt, false, 'Two different salt')
      chai.assert.equal(hashedPassphrase1.storedHash === hashedPassphrase2.storedHash, false, 'Two different salt')
    })

    it('Should generate the same derived key if the salt is a UInt8Array or Buffer.from(UInt8array)', async () => {
      const passphrase = 'secret'
      const salt1 = MasqCommon.crypto.genRandomBuffer(16)
      const salt2 = MasqCommon.crypto.getBuffer(salt1)

      const hashedPassphrase1 = await MasqCommon.crypto.derivePassphrase(passphrase, salt1)
      const hashedPassphrase2 = await MasqCommon.crypto.derivePassphrase(passphrase, salt2)
      chai.assert.isTrue(hashedPassphrase1.salt === hashedPassphrase2.salt, 'Two identical salt')
      chai.assert.isTrue(hashedPassphrase1.storedHash === hashedPassphrase2.storedHash, 'Two identical hashed Passphrase')
    })
  })

  context('AES operations and key export/import', () => {
    it('Should generate an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await MasqCommon.crypto.genAESKey()
      chai.assert.equal(key.type, 'secret', 'Secret key')
      chai.assert.isTrue(key.extractable, 'Key is extractable by default to allow export or wrap')
    })

    it('Should generate and export (in raw format by default) an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await MasqCommon.crypto.genAESKey()
      const rawKey = await MasqCommon.crypto.exportKey(key)
      chai.assert.lengthOf(rawKey, 16, 'Default size is 128 bits')
    })

    it('Should generate and export (in raw format by default) an extractable AES key cryptokey with default settings (AES-GCM 256 bits)', async () => {
      const key = await MasqCommon.crypto.genAESKey(true, 'AES-GCM', 256)
      const rawKey = await MasqCommon.crypto.exportKey(key)
      chai.assert.lengthOf(rawKey, 32, 'Default size is 256 bits')
    })

    it('Should generate and export in raw format an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await MasqCommon.crypto.genAESKey()
      const rawKey = await MasqCommon.crypto.exportKey(key, 'raw')
      chai.assert.lengthOf(rawKey, 16, 'Default size is 128 bits')
    })

    it('Should reject if the key is not a CryptoKey', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.crypto.encrypt([2, 3], { data: 'hello' })
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NOCRYPTOKEY, 'Reject if given key is not a CryptoKey')
    })

    it('Should encrypt a message and encode with default format (hex)', async () => {
      const message = { data: 'hello' }
      const key = await MasqCommon.crypto.genAESKey()
      const ciphertext = await MasqCommon.crypto.encrypt(key, message)
      chai.assert.lengthOf(ciphertext.iv, 32, 'Default size is 32 for hex format (128 bits iv)')
    })

    it('Should encrypt a message and encode with base64 format ', async () => {
      const message = { data: 'hello' }
      const key = await MasqCommon.crypto.genAESKey()
      const ciphertext = await MasqCommon.crypto.encrypt(key, message, 'base64')
      chai.assert.equal(ciphertext.iv.slice(-1), '=', 'Last charachter of base64 is always =')
    })

    it('Should encrypt and decrypt a message with default parameters', async () => {
      const message = { data: 'hello' }
      const key = await MasqCommon.crypto.genAESKey()
      const ciphertext = await MasqCommon.crypto.encrypt(key, message)
      const plaintext = await MasqCommon.crypto.decrypt(key, ciphertext)
      chai.assert.deepEqual(plaintext, message, 'Must get the initial message after decryption')
    })

    it('Should generate/encrypt/export/import/decrypt with raw format for key export', async () => {
      const message = { data: 'hello' }
      const key = await MasqCommon.crypto.genAESKey()
      const ciphertext = await MasqCommon.crypto.encrypt(key, message)
      const rawKey = await MasqCommon.crypto.exportKey(key)
      const cryptoKey = await MasqCommon.crypto.importKey(rawKey)
      const plaintext = await MasqCommon.crypto.decrypt(cryptoKey, ciphertext)
      chai.assert.deepEqual(plaintext, message, 'Must get the initial message after decryption')
    })

    it('Should generate/encrypt/export/import/decrypt with jwk format for key export', async () => {
      const message = { data: 'hello' }
      const key = await MasqCommon.crypto.genAESKey()
      const ciphertext = await MasqCommon.crypto.encrypt(key, message)
      const jwkKey = await MasqCommon.crypto.exportKey(key, 'jwk')
      const cryptoKey = await MasqCommon.crypto.importKey(jwkKey, 'jwk')
      const plaintext = await MasqCommon.crypto.decrypt(cryptoKey, ciphertext)
      chai.assert.deepEqual(plaintext, message, 'Must get the initial message after decryption')
    })
  })
})
