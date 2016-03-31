const tweetnacl = require('tweetnacl');
const secretkeyEncryption = require('../index');

const keyPair = tweetnacl.sign.keyPair();
const password = 'test password';

secretkeyEncryption.encryptSecretKey(password, keyPair.secretKey, function(encryptedSecretKeyBundle) {
  console.log(JSON.stringify(encryptedSecretKeyBundle));
});
