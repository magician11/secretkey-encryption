# secretkey-encryption

Encryption for secret keys that are generated by NaCl.

## API

All arrays of bytes are `Uint8Array`s.

### encryptSecretKey (password, secretKey, callback)

Arguments
* password - string or array of bytes
* secretKey - Uint8Array

When complete, the callback passed in is called with an object containing the following properties
* salt - Uint8Array with 32 random bytes
* encryptedSecretKey - Array of bytes
* nonce - Uint8Array with 24 random bytes

### decryptEncryptedSecretKey (password, encryptedSecretKeyBundle, callback)

Arguments
* password - string or array of bytes
* encryptedSecretKeyBundle - an object with parameters {salt, encryptedSecretKey, nonce}

Returns
* if the secret key was successfully decrypted, this function returns the secretKey (as an array of bytes)
* otherwise if decryption failed, then `false` is returned
