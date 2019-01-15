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

  context('Should derive a passphrase ', () => {
    let passphrase = 'mySecretPass'

    it('Should derive a passphrase [string] with default settings, gen MK and encrypt it ', async () => {
      const protectedMasterKey = await MasqCommon.crypto.genEncryptedMasterKey(passphrase)
      const { derivationParams, encryptedMasterKey } = protectedMasterKey
      const { salt, iterations, hashAlgo } = derivationParams
      chai.assert.equal(hashAlgo, 'SHA-256', 'Default hash algo is SHA-256')
      chai.assert.equal(iterations, 100000, 'Default iteration is 100000')
      chai.assert.lengthOf(salt, 32, 'Default salt is 128 bits array, 32 bytes as hex string')
      chai.assert.exists(encryptedMasterKey.iv)
      chai.assert.exists(encryptedMasterKey.ciphertext)
    })

    it('Should reject if passphrase is not a string or is empty', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await MasqCommon.crypto.genEncryptedMasterKey([])
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.NOPASSPHRASE, 'Reject if passphrase is not a string')
    })

    it('Should return the MK (an Array) if the given passphrase is the same as the stored one', async () => {
      const protectedMK = await MasqCommon.crypto.genEncryptedMasterKey(passphrase)
      const MK = await MasqCommon.crypto.decryptMasterKey(passphrase, protectedMK)
      chai.assert.exists(MK, 'The check operation should return the MK')
      chai.assert.lengthOf(MK, 16, 'Default AES key is 128 bits long ')
    })

    it('Should derive a key from passphrase, gen MK, enc/dec a value', async () => {
      const protectedMK = await MasqCommon.crypto.genEncryptedMasterKey(passphrase)
      const MK = await MasqCommon.crypto.decryptMasterKey(passphrase, protectedMK)
      const cryptokey = await MasqCommon.crypto.importKey(MK)
      const data = { 'hello': 'world' }
      const enc = await MasqCommon.crypto.encrypt(cryptokey, data)
      chai.assert.exists(enc.iv, 'iv must exist')
      chai.assert.exists(enc.ciphertext, 'ciphertext must exist')

      // Just to be sure that everything is working well.
      const sameMK = await MasqCommon.crypto.decryptMasterKey(passphrase, protectedMK)
      const sameCryptokey = await MasqCommon.crypto.importKey(sameMK)
      const dec = await MasqCommon.crypto.decrypt(sameCryptokey, enc)
      chai.assert.deepEqual(dec, data, 'Must be the same')
    })

    it('Should reject if the given passphrase is NOT the same as the stored one', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const protectedMK = await MasqCommon.crypto.genEncryptedMasterKey(passphrase)
        await MasqCommon.crypto.decryptMasterKey(passphrase + 'modifed', protectedMK)
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, MasqCommon.errors.ERRORS.WRONGPASSPHRASE, 'Reject if wrong passphrase')
    })

    it('Should reject if the any property of protectedMK is missing or empty', async () => {
      let err = '_ERROR_NOT_THROWN_'
      try {
        await MasqCommon.crypto.decryptMasterKey('secretPassphraseCandidate', {})
      } catch (error) {
        err = error.name
      }
      chai.assert.equal(err, MasqCommon.errors.ERRORS.WRONGPARAMETER, 'A requried property is missing')
    })

    it('The salt and protectedMK must be different for two consecutive call to genEncryptedMasterKey even with the same passphrase', async () => {
      const passphrase = 'secret'
      const protectedMK1 = await MasqCommon.crypto.genEncryptedMasterKey(passphrase)
      const protectedMK2 = await MasqCommon.crypto.genEncryptedMasterKey(passphrase)
      chai.assert.equal(protectedMK1.derivationParams.salt === protectedMK2.derivationParams.salt, false, 'Two different salt')
      chai.assert.equal(protectedMK1.encryptedMasterKey.iv === protectedMK2.encryptedMasterKey.iv, false, 'Two different iv')
      chai.assert.isFalse(protectedMK1.encryptedMasterKey.ciphertext === protectedMK2.encryptedMasterKey.ciphertext, false, 'Two different ciphertext')
    })

    it('Should generate the same derived key if the salt is a UInt8Array or Buffer.from(UInt8array)', async () => {
      const passphrase = 'secret'
      const salt1 = MasqCommon.crypto.genRandomBuffer(16)
      const salt2 = MasqCommon.crypto.getBuffer(salt1)

      const protectedMK1 = await MasqCommon.crypto.genEncryptedMasterKey(passphrase, salt1)
      const protectedMK2 = await MasqCommon.crypto.genEncryptedMasterKey(passphrase, salt2)
      chai.assert.isTrue(protectedMK1.derivationParams.salt === protectedMK2.derivationParams.salt, 'Two identical salt')
      chai.assert.isTrue(protectedMK1.storedHash === protectedMK2.storedHash, 'Two identical hashed Passphrase')
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
      chai.assert.lengthOf(ciphertext.iv, 24, 'Default size is 24 for hex format (96 bits iv), specific for AES-GCM')
    })

    it('Should encrypt a message and encode with base64 format ', async () => {
      const message = { data: 'hello' }
      const key = await MasqCommon.crypto.genAESKey()
      const ciphertext = await MasqCommon.crypto.encrypt(key, message, 'base64')

      chai.assert.equal(ciphertext.ciphertext.slice(-1), '=', 'Last character of base64 is always =')
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
