const tweetnacl = require('tweetnacl');
const scrypt = require('scrypt-async');

const dkLen = 32;
const interruptStep = 0;
const logN = 16;
const blockSize = 8;

function encryptSecretKey(password, secretKey, callback) {
  const salt = tweetnacl.randomBytes(32);
  const nonce = new Uint8Array(24);
  scrypt(password, salt, logN, blockSize, dkLen, interruptStep, (derivedKey) => {
    const encryptedSecretKey = tweetnacl.secretbox(secretKey, nonce, new Uint8Array(derivedKey));
    callback({ salt, nonce, encryptedSecretKey });
  });
}

function decryptEncryptedSecretKey(password, encryptedSecretKeyBundle, callback) {
  scrypt(password, encryptedSecretKeyBundle.salt, logN, blockSize, dkLen, interruptStep, (derivedKey) => {
    const secretKey = tweetnacl.secretbox.open(encryptedSecretKeyBundle.encryptedSecretKey, encryptedSecretKeyBundle.nonce, new Uint8Array(derivedKey));
    callback(secretKey);
  });
}

module.exports = { encryptSecretKey, decryptEncryptedSecretKey };
