'use strict';

var promisifyAll = require('bluebird').promisifyAll;
var hyperdb = require('hyperdb');
var rai = require('random-access-idb');

module.exports = {
  dbReady: dbReady,
  dbExists: dbExists,
  createPromisifiedHyperDB: createPromisifiedHyperDB
};

function createPromisifiedHyperDB(name, hexKey) {
  var keyBuffer = hexKey ? Buffer.from(hexKey, 'hex') : null;
  return promisifyAll(hyperdb(rai(name), keyBuffer, { valueEncoding: 'json' }));
}

function dbReady(db) {
  return new Promise(function (resolve, reject) {
    db.on('ready', function () {
      resolve();
    });
  });
}

function dbExists(dbName) {
  return new Promise(function (resolve, reject) {
    var req = window.indexedDB.open(dbName);
    var existed = true;
    req.onsuccess = function () {
      req.result.close();
      if (!existed) {
        window.indexedDB.deleteDatabase(dbName);
      }
      resolve(existed);
    };
    req.onupgradeneeded = function () {
      existed = false;
    };
    req.onerror = function (err) {
      reject(err);
    };
  });
}