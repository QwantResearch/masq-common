class MasqError extends Error {
  constructor (code, details, underlyingError) {
    super()
    if (details instanceof Error) {
      underlyingError = details
      details = undefined
    }
    this.message = makeErrorMessage(code, details)

    this.code = code

    this.underlyingError = underlyingError
    this.details = details
  }
}

const makeErrorMessage = (code, details) => {
  let msg
  if (code) {
    if (MasqError.messages[code]) {
      msg = MasqError.messages[code]
    } else {
      msg = 'Unknown error with code "' + code + '"'
    }
  } else {
    msg = 'Error with no error code'
  }

  if (details) {
    msg = msg + ' : ' + details
  }

  return msg
}

MasqError.messages = {
  UNDEFINED_ERROR: 'Error with undefined type',
  INVALID_ENCODING_FORMAT: 'Supported encoding formats: hex and base64',
  WRONG_PARAMETER: 'The given object has wrong properties',
  WRONG_FUNCTION_ARGUMENTS: 'Wrong function arguments',
  NOT_LOGGED_IN: 'Not logged into Masq',
  NOT_CONNECTED: 'Not connected to Masq',
  UNABLE_TO_DECRYPT: 'Unable to decrypt data',
  UNABLE_TO_ENCRYPT: 'Unable to encrypt data',
  WRONG_MESSAGE: 'Wrong message received',
  WRONG_PASSPHRASE: 'Wrong passphrase',
  MASQ_ACCESS_REFUSED_BY_USER: 'Masq access refused by the user',
  INVALID_KEY: 'Invalid key',
  INVALID_CRYPTOKEY: 'Invalid crypto key',
  NO_DB: 'No DB provided',
  NO_NONCE: 'No nonce provided',
  NO_ENCRYPTION_KEY: 'No encryption key provided',
  MISSING_PROFILE_ID: 'Misssing profile id',
  MISSING_RESOURCE_ID: 'Missing resource id',
  INVALID_PASSPHRASE: 'Invalid Passphrase',
  USERNAME_ALREADY_TAKEN: 'This username already exists',
  AUTHORIZE_DB_KEY_FAILED: 'Authorization of db key for write access failed',
  PROFILE_NOT_OPENED: 'Not logged in and trying to execute a function only accessible when logged in',
  DISCONNECTED_DURING_LOGIN: 'Disconnected during login procedure',
  SIGNALLING_SERVER_ERROR: 'Could not connect to the signalling server',
  REPLICATION_SIGNALLING_ERROR: 'Lost connection to signalling server during replication'
}

MasqError.UNDEFINED_ERROR = 'UNDEFINED_ERROR'
MasqError.INVALID_ENCODING_FORMAT = 'INVALID_ENCODING_FORMAT'
MasqError.WRONG_PARAMETER = 'WRONG_PARAMETER'
MasqError.WRONG_FUNCTION_ARGUMENTS = 'WRONG_FUNCTION_ARGUMENTS'
MasqError.NOT_LOGGED_IN = 'NOT_LOGGED_IN'
MasqError.NOT_CONNECTED = 'NOT_CONNECTED'
MasqError.UNABLE_TO_DECRYPT = 'UNABLE_TO_DECRYPT'
MasqError.UNABLE_TO_ENCRYPT = 'UNABLE_TO_ENCRYPT'
MasqError.WRONG_MESSAGE = 'WRONG_MESSAGE'
MasqError.WRONG_PASSPHRASE = 'WRONG_PARAMETER'
MasqError.MASQ_ACCESS_REFUSED_BY_USER = 'MASQ_ACCESS_REFUSED_BY_USER'
MasqError.INVALID_KEY = 'INVALID_KEY'
MasqError.INVALID_CRYPTOKEY = 'INVALID_CRYPTOKEY'
MasqError.NO_DB = 'NO_DB'
MasqError.NO_NONCE = 'NO_NONCE'
MasqError.NO_ENCRYPTION_KEY = 'NO_ENCRYPTION_KEY'
MasqError.MISSING_PROFILE_ID = 'MISSING_PROFILE_ID'
MasqError.MISSING_RESOURCE_ID = 'MISSING_RESOURCE_ID'
MasqError.INVALID_PASSPHRASE = 'INVALID_PASSPHRASE'
MasqError.USERNAME_ALREADY_TAKEN = 'USERNAME_ALREADY_TAKEN'
MasqError.AUTHORIZE_DB_KEY_FAILED = 'AUTHORIZE_DB_KEY_FAILED'
MasqError.PROFILE_NOT_OPENED = 'PROFILE_NOT_OPENED'
MasqError.DISCONNECTED_DURING_LOGIN = 'DISCONNECTED_DURING_LOGIN'
MasqError.SIGNALLING_SERVER_ERROR = 'SIGNALLING_SERVER_ERROR'
MasqError.REPLICATION_SIGNALLING_ERROR = 'REPLICATION_SIGNALLING_ERROR'

/**
   * Use this fonction to check if the required parameters
   * are present in the received object.
   * @param {object} obj - The object we want to check
   * @param {array} parameters - The array with all the keys we want to test
   * @returns {masqError}
   */
const checkObject = (obj, parameters) => {
  for (let i in parameters) {
    if (obj[parameters[i]] === undefined) {
      throw new MasqError(MasqError.WRONG_PARAMETER, `The parameter ${parameters[i]} is required`)
    }
  }
}

export { checkObject, MasqError }
