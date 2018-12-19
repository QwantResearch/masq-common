'use strict';

var promisifyAll = require('bluebird').promisifyAll;
var hyperdb = require('hyperdb');
var rai = require('random-access-idb');

module.exports = {
  dbReady: dbReady,
  dbExists: dbExists,
  createPromisifiedHyperDB: createPromisifiedHyperDB,
  getHashParams: getHashParams
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

function getHashParams(link) {
  var url = new URL(link);
  var hash = url.hash.slice(2);
  var hashParamsArr = JSON.parse(Buffer.from(hash, 'base64').toString('utf8'));
  if (typeof hashParamsArr === 'array' || hashParamsArr.length !== 4) {

    throw new Error('Wrong login URL');
  }
  var hashParamsObj = {
    appName: hashParamsArr[0],
    requestType: hashParamsArr[1],
    channel: hashParamsArr[2],
    key: hashParamsArr[3]
  };
  hashParamsObj.key = Buffer.from(hashParamsObj.key, 'base64');
  return hashParamsObj;
}