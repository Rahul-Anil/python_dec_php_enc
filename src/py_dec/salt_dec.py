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
    secret_key = PBKDF2(
        password, salt, 32, iterations, None, hmac_hash_module=SHA512
    )  # 32 byte string is returned

    # check if the secret key is 32 bytes
    assert len(secret_key) == 32, logger.error(
        f"Secret key length is {len(secret_key)} bytes it should be 32 bytes"
    )
    return secret_key


def salt_php_dec(
    json_base64_encoded: str,
    password: str,
    iterations: int,
    aes_mode: int,
    list_of_json_obj: list[str],
) -> str:
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
    logger.debug(f"dec_data: {dec_data}")

    # unpad and get plain text
    dec_data_unpadded = unpad(dec_data, AES.block_size)
    plain_text = dec_data_unpadded.decode("utf-8")
    return plain_text


def salt_php_dec_call():
    json_base64_encoded = "eyJpdiI6ImNkNGQ0NTc0Zjk4Yzc5YmY3MDdmMGYwMjRkNDg5ZmUyIiwiZXQiOiI2ZjY4YmNjMDcxZjUwMjMwNGQwMDI4MDU2MDAyOGZlMiIsInNhbHQiOiJjZjk4ZjQ0MmMwNzdjZWQ1YWJlNTlkMTM0YThjMGVhMSJ9"
    list_of_json_obj = ["iv", "et", "salt"]
    aes_mode = AES.MODE_CBC
    password = "garchomp"
    iterations = 100

    try:
        dt = salt_php_dec(
            json_base64_encoded,
            password,
            iterations,
            aes_mode,
            list_of_json_obj,
        )
    except ValueError as e:
        logger.error(e)
        print("Exiting...")
        sys.exit(1)

    logger.debug("plain text: %s", dt)
    assert dt == "pokemon", logger.error(f"decrypted data is {dt} not pokemon")
    logger.info("DEC SALT WORKS!!")


def main():
    salt_php_dec_call()


if __name__ == "__main__":
    main()
