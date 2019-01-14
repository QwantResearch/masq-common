const ERRORS = {
  NOT_LOGGED_IN: 'Not logged into Masq',
  NOT_CONNECTED: 'Not connected to Masq',
  UNABLE_TO_DECRYPT: 'Unable to decrypt data',
  WRONG_MESSAGE: 'Wrong message received',
  MASQ_ACCESS_REFUSED_BY_USER: 'Masq access refused by the user',
  INVALID_KEY: 'Invalid key',
  MISSING_PROFILE_ID: 'Misssing profile id',
  MISSING_RESOURCE_ID: 'Missing resource id',
  INVALID_PASSPHRASE: 'Invalid Passphrase',
  USERNAME_ALREADY_TAKEN: 'This username already exists',
  AUTHORIZE_DB_KEY_FAILED: 'Authorization of db key for write access failed',
  PROFILE_NOT_OPENED: 'Not logged in and trying to execute a function only accessible when logged in',
  DISCONNECTED_DURING_LOGIN: 'Disconnected during login procedure'
}

class MasqError extends Error {
  constructor (type, details) {
    super()
    this.type = type
    this.details = details
  }

  getMessage () {
    if (!this.type) {
      return 'Unknown error'
    }
    let msg = ERRORS[this.type]
    if (!msg) {
      msg = `Unknown error with type "${this.type}"`
    }

    if (this.details) {
      msg = msg + ' : ' + this.details
    }

    return msg
  }
}

/**
   * Use this fonction to check if the required parameters
   * are present in the received object.
   * @param {object} obj - The object we want to check
   * @param {array} parameters - The array with all the keys we want to test
   * @returns {masqError}
   */
const checkObject = (obj, parameters) => {
  for (let i in parameters) {
    if (typeof obj[parameters[i]] !== 'boolean') {
      if (!obj[parameters[i]] || obj[parameters[i]] === '') {
        const error = {
          message: `The parameter ${parameters[i]} is required`,
          name: ERRORS.WRONGPARAMETER
        }
        throw error
      }
    }
  }
}

module.exports.checkObject = checkObject
module.exports.ERRORS = ERRORS
module.exports.MasqError = MasqError
