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
import os
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from logTemplate import make_logger

# set current working directory
parent_directory_path = os.path.dirname(__file__)
set_cwd_path = os.path.abspath(os.path.join(parent_directory_path, os.pardir))
os.chdir(set_cwd_path)

LOGGER_PATH = "logging-config.yaml"
LOGGER_NAME = "py_dec_php_enc-DEVELOPMENT"
try:
    logger = make_logger.init_logger(LOGGER_PATH, "py_dec_php_enc-DEVELOPMENT")
except (ValueError, FileNotFoundError) as error:
    print("SETUP ERROR: COULD NOT INITIALIZE LOGGER")
    print(error)
    sys.exit(1)


def generate_secret_key(salt: bytes, iterations: int, password: str) -> bytes:
    """Generate secret key from salt and password

    uses PBKDF2 to generate the secret key from the salt and password

    Args:
        salt(bytes): salt to used to generate the secret key
        iterations(int): number of iterations to be used in PBKDF2
        password(str): password

    Returns:
        secret_key(bytes)

    Raises:
        ValueError: if the length of the secret key is not 32 bytes for AES-256
    """
    secret_key = PBKDF2(
        password, salt, 32, iterations, None, hmac_hash_module=SHA512
    )  # 32 byte string is returned

    if len(secret_key) != 32:
        raise ValueError(
            "Secret key length is {len(secret_key)} bytes it should be 32 bytes"
        )
    return secret_key


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
    secret_key = generate_secret_key(bin_salt, iterations, password)

    # create decrypt cipher obj
    decrypt_cipher = AES.new(secret_key, aes_mode, bin_iv)

    # decrypt data
    dec_data = decrypt_cipher.decrypt(bin_et)

    # unpad and get plain text
    dec_data_unpadded = unpad(dec_data, AES.block_size)
    plain_text = dec_data_unpadded.decode("utf-8")
    return plain_text


def salt_py_dec_call():
    """test caller for decrypt_aes256_cbc()"""
    json_base64_encoded = "eyJpdiI6ImNkNGQ0NTc0Zjk4Yzc5YmY3MDdmMGYwMjRkNDg5ZmUyIiwiZXQiOiI2ZjY4YmNjMDcxZjUwMjMwNGQwMDI4MDU2MDAyOGZlMiIsInNhbHQiOiJjZjk4ZjQ0MmMwNzdjZWQ1YWJlNTlkMTM0YThjMGVhMSJ9"
    list_of_json_obj = ["iv", "et", "salt"]
    password = "garchomp"
    iterations = 100

    try:
        dt = decrypt_aes256_cbc(
            json_base64_encoded,
            password,
            iterations,
            list_of_json_obj,
        )
    except ValueError as e:
        logger.error(e)
        print("Exiting...")
        sys.exit(1)

    logger.debug("plain text: %s", dt)
    assert dt == "pokemon", logger.error("decrypted data is %s not pokemon", dt)


def main():
    """main"""
    salt_php_dec_call()


if __name__ == "__main__":
    main()
