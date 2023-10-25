"""Decryt AES-256-CBC encrypted data from PHP openssl_encrypt() function with s
salt

Decrypts a JSON string with data from PHP opeenssl_encrypt() function with salt.
Example usage is shown in the salt_php_dec_call() function.
Its php encrypt counterpart is in src/php_enc/salt_enc.php

Usage:
    decrypt_aes256_cbc(
        json_base64_encoded, 
        password, iterations, 
        list_of_json_obj
    )
"""
import base64
import binascii
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from helpers import salt_helpers


def decrypt_aes256_cbc(
    json_base64_encoded: str,
    password: str,
    iterations: int,
    list_of_json_obj: list[str],
) -> str:
    """decryption function for AES-256-CBC with salt for secret key generation

    Args:
        json_base_64_encoded(str): json string with base64 encoded data
        password(str): password
        iterations(int): number of iterations to be used in PBKDF2
        list_of_json_obj(list[str]): list of json object keys that are present
            in JSON

    Returns:
        plain_text(str): decrypted plain text

    Raises:
        ValueError: if the req keys are not present in the json.
    """
    aes_mode = AES.MODE_CBC  # Only CBC mode is supported as of now
    # decode json from base64 to utf-8
    json_enc = base64.b64decode(json_base64_encoded).decode("utf-8")
    # check if the req keys are available
    if not all(obj in json_enc for obj in list_of_json_obj):
        raise ValueError("Req keys in json_enc string not found")

    # get hex data from json
    enc_data = json.loads(json_enc)
    hex_et = enc_data["et"]
    hex_iv = enc_data["iv"]
    hex_salt = enc_data["salt"]

    # convert hex to bytes
    bin_et = binascii.unhexlify(hex_et)
    bin_iv = binascii.unhexlify(hex_iv)
    bin_salt = binascii.unhexlify(hex_salt)

    # generate secret key
    secret_key = salt_helpers.generate_secret_key(
        bin_salt, iterations, password
    )

    # create decrypt cipher obj
    decrypt_cipher = AES.new(secret_key, aes_mode, bin_iv)

    # decrypt data
    dec_data = decrypt_cipher.decrypt(bin_et)

    # unpad and get plain text
    dec_data_unpadded = unpad(dec_data, AES.block_size)
    plain_text = dec_data_unpadded.decode("utf-8")
    return plain_text
