# Python dec PHP enc

## Note:
- the current version only works using AES-256-CBC encryption.

## Encryption 
Use the php program located in `src/php_enc/salt_enc.php`, here the `encrypt_aes256_CBC()` should be used to encrypt the data, this will create a
base64 encoded json string as the output which contains the encrypted data and iv for the decryption, and the salt for the secret key derivation.

To see how to use the function see the `salt_php_enc_call()` function in the same file.

## Decryption
Use the python program location in `src/py_dec/salt_dec.py`, here the `decrypt_aes256_CBC()` should be used to decrypt the data, this will take the
base64 encoded json string as the input and return the decrypted data as a string in plain text (utf-8).

To see how to use the function see the `salt_py_dec_call()` function in the same file.

## TODO:
