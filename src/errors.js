const ERRORS = {
  NOLOGGEDUSER: 'No logged user',
  WRONGPARAMETER: 'One or several parameters are wrong',
  WRONGPASSPHRASE: 'The given passphrase is wrong',
  NOURLPROVIDED: 'No url provided',
  EMPTYUSERLIST: 'User list is empty',
  NOUSERNAME: 'No username provided',
  NOPASSPHRASE: 'No passphrase provided',
  EXISTINGUSERNAME: 'The username already exists',
  EXISTINGURL: 'The application url already exists',
  FUNCTIONNOTDEFINED: 'The function is not defined',
  USERNAMENOTFOUND: 'The username does not exist',
  NOEXISTINGKEY: 'The required key does not exist',
  NOVALUE: 'No value provided',
  NOTOKEN: 'Token does not exist',
  BADTOKEN: 'Token is not valid',
  BADREQUEST: 'Bad request',
  NOTAUTHORIZED: 'Not authorized',
  NOCRYPTOKEY: 'Not a cryptokey',
  ENCRYPTIONERROR: 'Encryption error',
  DECRYPTIONERROR: 'Decryption error',
  NOIMPORTRULES: 'No import rules provided'
}

/**
    * @typedef MasqError
    * @type {Object}
    * @property {boolean} error
    * @property {int} status - THe status of the error
    * @property {string} message - The status of the error
    * @property {string} name - The name of the error
    * @property {string} stack - The stack
    */

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
          name: ERRORS.WRONGPARAMETER,
          error: true
        }
        throw error
      }
    }
  }
}

/**
   * Generate a masqError object, the name must be
   * one of ERRORS.
   *
   * @param {string} name - The name of the error
   * @param {string} message
   * @param {string} status
   */
const generateError = (name, message, status) => {
  let err = {
    name: name || '',
    message: message || '',
    status: status || '',
    error: true
  }
  return err
}

module.exports.ERRORS = ERRORS
module.exports.generateError = generateError
module.exports.checkObject = checkObject
