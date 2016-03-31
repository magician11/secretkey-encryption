const tweetnacl = require('tweetnacl');
tweetnacl.util = require('tweetnacl-util');
const secretkeyEncryption = require('../index');

const keyPair = tweetnacl.sign.keyPair();
const encodedSecretKey = tweetnacl.util.encodeBase64(keyPair.secretKey);
console.log(`Original secret key\n${encodedSecretKey}\n`);

const password = 'test password';

secretkeyEncryption.encryptSecretKey(password, keyPair.secretKey, (encryptedSecretKeyBundle) => {
  console.log(`Encrypted Secret Key Bundle (as JSON string)\n${JSON.stringify(encryptedSecretKeyBundle)}\n`);
  secretkeyEncryption.decryptEncryptedSecretKey('test password', encryptedSecretKeyBundle, (secretKey) => {
    if (secretKey === false) {
      console.log('Error! Decryption of secret key failed.');
    } else {
      console.log(`Decrypted secret key\n${tweetnacl.util.encodeBase64(secretKey)}\n`);
      console.log('Success! Secret successfully decrypted!');
    }
  });
});
