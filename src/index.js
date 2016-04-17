import tweetnacl from 'tweetnacl';
import scrypt from 'scrypt-async';

function encryptSecretKey(password, secretKey, logN = 16, blockSize = 8, dkLen = 32, interruptStep = 0) {
  return new Promise((resolve, reject) => {
    const salt = tweetnacl.randomBytes(32);
    scrypt(password, salt, logN, blockSize, dkLen, interruptStep, (derivedKey) => {
      const nonce = new Uint8Array(24);
      const encryptedSecretKey = tweetnacl.secretbox(secretKey, nonce, new Uint8Array(derivedKey));
      resolve({ encryptedSecretKey, salt, nonce, logN, blockSize, dkLen, interruptStep });
    });
  });
}

function decryptEncryptedSecretKey(password, encryptedSecretKeyBundle) {
  return new Promise((resolve, reject) => {
    scrypt(password, encryptedSecretKeyBundle.salt, encryptedSecretKeyBundle.logN, encryptedSecretKeyBundle.blockSize, encryptedSecretKeyBundle.dkLen, encryptedSecretKeyBundle.interruptStep, (derivedKey) => {
      const secretKey = tweetnacl.secretbox.open(encryptedSecretKeyBundle.encryptedSecretKey, encryptedSecretKeyBundle.nonce, new Uint8Array(derivedKey));
      if (secretKey) {
        resolve(secretKey);
      } else {
        reject('Decryption of the encrypted secret key failed.');
      }
    });
  });
}

module.exports = { encryptSecretKey, decryptEncryptedSecretKey };
