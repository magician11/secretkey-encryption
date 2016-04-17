const tweetnacl = require('tweetnacl');
tweetnacl.util = require('tweetnacl-util');
const secretkeyEncryption = require('../lib/index');

const keyPair = tweetnacl.sign.keyPair();
const encodedSecretKey = tweetnacl.util.encodeBase64(keyPair.secretKey);
console.log(`Original secret key\n${encodedSecretKey}\n`);

const password = 'test password';

secretkeyEncryption.encryptSecretKey(password, keyPair.secretKey)
.then((encryptedSecretKeyBundle) => {
  console.log(`Encrypted Secret Key Bundle (as JSON string)\n${JSON.stringify(encryptedSecretKeyBundle)}\n`);
  return secretkeyEncryption.decryptEncryptedSecretKey('test password', encryptedSecretKeyBundle);
})
.then((secretKey) => {
  console.log(`Decrypted secret key\n${tweetnacl.util.encodeBase64(secretKey)}\n`);
  console.log('Success! Secret successfully decrypted!');
})
.catch((error) => {
  console.log(error);
});
