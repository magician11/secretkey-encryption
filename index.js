const chloride = require('chloride/small');
const scrypt = require('scrypt-async');
const crypto = require('crypto');

const dkLen = 32;
const interruptStep = 0;

function encryptSecretKey(password, secretKey, callback) {
  const salt = crypto.randomBytes(32);
  const nonce = new Uint8Array(24);
  const logN = 16;
  const blockSize = 8;
  scrypt(password, salt, logN, blockSize, dkLen, interruptStep, (derivedKey) => {
    const encryptedSecretKey = chloride.crypto_secretbox(secretKey, nonce, new Uint8Array(derivedKey));
    callback({ salt, logN, blockSize, encryptedSecretKey });
  });
}

module.exports = {
  encryptSecretKey
};
