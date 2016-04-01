# secretkey-encryption

Encryption for secret keys that are generated by NaCl.

The secret key is encrypted by deriving a key from the supplied password using [scrypt-async](https://github.com/dchest/scrypt-async-js) and then using that key to encrypt the secret key with [TweetNaCl.js's secretbox function](TweetNaCl.js).

## API

All arrays of bytes are `Uint8Array`s.

### encryptSecretKey (password, secretKey, [logN], [r], [dkLen], [interruptStep], callback)

Arguments
* password - string or array of bytes
* secretKey - array of bytes
* logN (optional) - CPU/memory cost parameter (1 to 31). Defaults to 16.
* r (optional) - block size parameter. Defaults to 8.
* dkLen (optional) - length of derived key. Defaults to 32.
* interruptStep (optional) - steps to split calculation with timeouts. Defaults to 0.
* callback

When complete, the callback passed in is called with an object containing the following properties
* encryptedSecretKey - array of bytes
* salt - 32 random bytes
* nonce - 24 random bytes
* logN
* blockSize
* dkLen
* interruptStep

### decryptEncryptedSecretKey (password, encryptedSecretKeyBundle, callback)

Arguments
* password - string or array of bytes
* encryptedSecretKeyBundle - an object with parameters {encryptedSecretKey, salt, nonce, logN, blockSize, dkLen, interruptStep}

When complete, the callback is called with
* if the secret key was successfully decrypted, the secretKey (as an array of bytes)
* otherwise if decryption failed, then it's called with `false`
