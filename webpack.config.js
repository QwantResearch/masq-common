var path = require('path')

module.exports = {
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'masq-common.js',
    library: 'MasqCommon',
    libraryTarget: 'umd'
  },
  node: {
    fs: 'empty'
  }
}
