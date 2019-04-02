/* eslint-env mocha */
/* global MasqCommon */
/* global chai */

const { ERRORS } = MasqCommon.errors
const { crypto } = MasqCommon

describe('MasqCommon crypto', function () {
  context('Generating a random buffer (e.g. iv)', () => {
    it('Should generate a random buffer without length parameter', () => {
      const iv1 = crypto.genRandomBuffer()
      chai.assert.lengthOf(iv1, 16, 'Default length is 16')
    })

    it('Should generate a random buffer with a specific length parameter', () => {
      const iv2 = crypto.genRandomBuffer(8)
      chai.assert.lengthOf(iv2, 8, 'Array length is not 8')
    })
    it('Should generate a random buffer with a specific length parameter in hex format', () => {
      const buf1 = crypto.genRandomBufferAsStr(8, 'hex')
      chai.assert.lengthOf(buf1, 16)
    })
    it('Should generate a random buffer with a specific length parameter in base64 format', () => {
      const buf = crypto.genRandomBufferAsStr(8, 'base64')
      chai.assert.lengthOf(buf, 12)
    })
    it('Should reject if a wrong encoding format is given', () => {
      const toCall = () => crypto.genRandomBufferAsStr(8, 'base777')
      chai.expect(toCall).to.throw().with.property('type', ERRORS.INVALID_ENCODING_FORMAT)
    })
  })

  context('Should derive a passphrase ', () => {
    let passphrase = 'mySecretPass'

    it('Should derive a passphrase [string] with default settings, gen MK and encrypt it ', async () => {
      const protectedMasterKey = await crypto.genEncryptedMasterKeyAndNonce(passphrase)
      const { derivationParams, encryptedMasterKeyAndNonce } = protectedMasterKey
      const { salt, iterations, hashAlgo } = derivationParams
      chai.assert.equal(hashAlgo, 'SHA-256', 'Default hash algo is SHA-256')
      chai.assert.equal(iterations, 100000, 'Default iteration is 100000')
      chai.assert.lengthOf(salt, 32, 'Default salt is 128 bits array, 32 bytes as hex string')
      chai.assert.exists(encryptedMasterKeyAndNonce.iv)
      chai.assert.exists(encryptedMasterKeyAndNonce.ciphertext)
    })

    it('Should update the passphrase but keep the same MK and nonce ', async () => {
      const newPassphrase = 'newPassphrase'
      const protectedMasterKey = await crypto.genEncryptedMasterKeyAndNonce(passphrase)
      const { derivationParams, encryptedMasterKeyAndNonce } = protectedMasterKey
      const { iterations, hashAlgo } = derivationParams
      chai.assert.equal(hashAlgo, 'SHA-256', 'Default hash algo is SHA-256')
      chai.assert.equal(iterations, 100000, 'Default iteration is 100000')

      const { masterKey, nonce } = await crypto.decryptMasterKeyAndNonce(passphrase, protectedMasterKey)

      const protectedMasterKeyNewPass = await await crypto.updateMasterKeyAndNonce(passphrase, newPassphrase, protectedMasterKey)
      const masterKeyEncWithNewPass = protectedMasterKeyNewPass.encryptedMasterKeyAndNonce
      const decryptedMKAndNonceNewPass = await crypto.decryptMasterKeyAndNonce(newPassphrase, protectedMasterKeyNewPass)

      // Check if ciphertexts are not the same
      chai.assert.notEqual(encryptedMasterKeyAndNonce.ciphertext, masterKeyEncWithNewPass.ciphertext)
      chai.assert.equal(protectedMasterKeyNewPass.derivationParams.hashAlgo, 'SHA-256', 'Default hash algo is SHA-256')
      chai.assert.equal(protectedMasterKeyNewPass.derivationParams.iterations, 100000, 'Default iteration is 100000')

      // Check if the masterkey and nonce are the same
      chai.assert.equal(decryptedMKAndNonceNewPass.masterKey.toString('hex'), masterKey.toString('hex'))
      chai.assert.equal(decryptedMKAndNonceNewPass.nonce, nonce)
    })

    it('Should reject if passphrase is not a string or is empty', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await crypto.genEncryptedMasterKeyAndNonce([])
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.INVALID_PASSPHRASE, 'Reject if passphrase is not a string')
    })

    it('Should return the MK (an Array) and a nonce if the given passphrase is the same as the stored one', async () => {
      const protectedMK = await crypto.genEncryptedMasterKeyAndNonce(passphrase)
      const { masterKey, nonce } = await crypto.decryptMasterKeyAndNonce(passphrase, protectedMK)

      chai.assert.exists(masterKey, 'The check operation should return the MK')
      chai.assert.lengthOf(masterKey, 16, 'Default AES key is 128 bits long ')
      chai.assert.exists(nonce)
      chai.assert.lengthOf(nonce, 32)
    })

    it('Should derive a key from passphrase, gen MK, enc/dec a value', async () => {
      const protectedMK = await crypto.genEncryptedMasterKeyAndNonce(passphrase)
      const MKAndNonce = await crypto.decryptMasterKeyAndNonce(passphrase, protectedMK)
      const cryptokey = await crypto.importKey(MKAndNonce.masterKey)
      const data = { 'hello': 'world' }
      const enc = await crypto.encrypt(cryptokey, data)
      chai.assert.exists(enc.iv, 'iv must exist')
      chai.assert.exists(enc.ciphertext, 'ciphertext must exist')

      // Just to be sure that everything is working well.
      const sameMKAndNonce = await crypto.decryptMasterKeyAndNonce(passphrase, protectedMK)
      const sameCryptokey = await crypto.importKey(sameMKAndNonce.masterKey)
      const dec = await crypto.decrypt(sameCryptokey, enc)
      chai.assert.deepEqual(dec, data, 'Must be the same')
    })

    it('Should reject if the given passphrase is NOT the same as the stored one', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const protectedMK = await crypto.genEncryptedMasterKeyAndNonce(passphrase)
        await crypto.decryptMasterKeyAndNonce(passphrase + 'modifed', protectedMK)
      } catch (error) {
        err = error
      }

      chai.assert.strictEqual(err.type, ERRORS.WRONG_PASSPHRASE, 'Reject if wrong passphrase')
    })

    it('Should reject if the any property of protectedMK is missing or empty', async () => {
      let err = '_ERROR_NOT_THROWN_'
      try {
        await crypto.decryptMasterKeyAndNonce('secretPassphraseCandidate', {})
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.WRONG_PARAMETER, 'A requried property is missing')
    })

    it('The salt and protectedMK must be different for two consecutive call to genEncryptedMasterKeyAndNonce even with the same passphrase', async () => {
      const passphrase = 'secret'
      const protectedMK1 = await crypto.genEncryptedMasterKeyAndNonce(passphrase)
      const protectedMK2 = await crypto.genEncryptedMasterKeyAndNonce(passphrase)
      chai.assert.notStrictEqual(protectedMK1.derivationParams.salt, protectedMK2.derivationParams.salt, 'Two different salt')
      chai.assert.notStrictEqual(protectedMK1.encryptedMasterKeyAndNonce.iv, protectedMK2.encryptedMasterKeyAndNonce.iv, 'Two different iv')
      chai.assert.notStrictEqual(protectedMK1.encryptedMasterKeyAndNonce.ciphertext, protectedMK2.encryptedMasterKeyAndNonce.ciphertext, 'Two different ciphertext')
    })

    it('Should generate the same derived key if the salt is a UInt8Array or Buffer.from(UInt8array)', async () => {
      const passphrase = 'secret'
      const salt1 = crypto.genRandomBuffer(16)
      const salt2 = crypto.getBuffer(salt1)

      const protectedMK1 = await crypto.genEncryptedMasterKeyAndNonce(passphrase, salt1)
      const protectedMK2 = await crypto.genEncryptedMasterKeyAndNonce(passphrase, salt2)
      chai.assert.strictEqual(protectedMK1.derivationParams.salt, protectedMK2.derivationParams.salt, 'Two identical salt')
      chai.assert.strictEqual(protectedMK1.storedHash, protectedMK2.storedHash, 'Two identical hashed Passphrase')
    })
  })

  context('AES operations and key export/import', () => {
    it('Should generate an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await crypto.genAESKey()
      chai.assert.equal(key.type, 'secret', 'Secret key')
      chai.assert.isTrue(key.extractable, 'Key is extractable by default to allow export or wrap')
    })

    it('Should generate and export (in raw format by default) an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await crypto.genAESKey()
      const rawKey = await crypto.exportKey(key)
      chai.assert.lengthOf(rawKey, 16, 'Default size is 128 bits')
    })

    it('Should generate and export (in raw format by default) an extractable AES key cryptokey with default settings (AES-GCM 256 bits)', async () => {
      const key = await crypto.genAESKey(true, 'AES-GCM', 256)
      const rawKey = await crypto.exportKey(key)
      chai.assert.lengthOf(rawKey, 32, 'Default size is 256 bits')
    })

    it('Should generate and export in raw format an extractable AES key cryptokey with default settings (AES-GCM 128 bits)', async () => {
      const key = await crypto.genAESKey()
      const rawKey = await crypto.exportKey(key, 'raw')
      chai.assert.lengthOf(rawKey, 16, 'Default size is 128 bits')
    })

    it('Should reject if the key is not a CryptoKey', async () => {
      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        await crypto.encrypt([2, 3], { data: 'hello' })
      } catch (error) {
        err = error
      }
      chai.assert.equal(err.type, ERRORS.INVALID_CRYPTOKEY, 'Reject if given key is not a CryptoKey')
    })

    it('Should encrypt a message and encode with default format (hex)', async () => {
      const message = { data: 'hello' }
      const key = await crypto.genAESKey()
      const ciphertext = await crypto.encrypt(key, message)
      chai.assert.lengthOf(ciphertext.iv, 24, 'Default size is 24 for hex format (96 bits iv), specific for AES-GCM')
    })

    it('Should encrypt a message and encode with base64 format ', async () => {
      const message = { data: 'hello' }
      const key = await crypto.genAESKey()
      const ciphertext = await crypto.encrypt(key, message, 'base64')

      chai.assert.equal(ciphertext.ciphertext.slice(-1), '=', 'Last character of base64 is always =')
    })

    it('Should encrypt and decrypt a message with default parameters', async () => {
      const message = { data: 'hello' }
      const key = await crypto.genAESKey()
      const ciphertext = await crypto.encrypt(key, message)
      const plaintext = await crypto.decrypt(key, ciphertext)
      chai.assert.deepEqual(plaintext, message, 'Must get the initial message after decryption')
    })

    it('Should generate/encrypt/export/import/decrypt with raw format for key export', async () => {
      const message = { data: 'hello' }
      const key = await crypto.genAESKey()
      const ciphertext = await crypto.encrypt(key, message)
      const rawKey = await crypto.exportKey(key)
      const cryptoKey = await crypto.importKey(rawKey)
      const plaintext = await crypto.decrypt(cryptoKey, ciphertext)
      chai.assert.deepEqual(plaintext, message, 'Must get the initial message after decryption')
    })

    it('Should generate/encrypt/export/import/decrypt with jwk format for key export', async () => {
      const message = { data: 'hello' }
      const key = await crypto.genAESKey()
      const ciphertext = await crypto.encrypt(key, message)
      const jwkKey = await crypto.exportKey(key, 'jwk')
      const cryptoKey = await crypto.importKey(jwkKey, 'jwk')
      const plaintext = await crypto.decrypt(cryptoKey, ciphertext)
      chai.assert.deepEqual(plaintext, message, 'Must get the initial message after decryption')
    })
    it('Should fail to decrypt a message with default parameters (wrong iv)', async () => {
      const message = { data: 'hello' }
      const key = await crypto.genAESKey()
      const ciphertext = await crypto.encrypt(key, message)

      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        ciphertext.iv = ciphertext.iv.slice(0, 10)
        await crypto.decrypt(key, ciphertext)
      } catch (error) {
        err = error
      }

      chai.assert.equal(err.type, ERRORS.UNABLE_TO_DECRYPT, 'Reject if wrong iv')
    })
    it('Should fail to decrypt a message with default parameters (wrong key)', async () => {
      const message = { data: 'hello' }
      const key = await crypto.genAESKey()
      const ciphertext = await crypto.encrypt(key, message)

      let err = { type: '_ERROR_NOT_THROWN_' }
      try {
        const key2 = await crypto.genAESKey()
        await crypto.decrypt(key2, ciphertext)
      } catch (error) {
        err = error
      }

      chai.assert.equal(err.type, ERRORS.UNABLE_TO_DECRYPT, 'Reject if wrong key')
    })
  })
})
