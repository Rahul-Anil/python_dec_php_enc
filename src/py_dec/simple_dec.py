import base64
import binascii
import json
import os
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
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


def simple_php_dec(
    json_enc: str, key: bytes, aes_mode: int, list_of_json_obj: list[str]
) -> str:
    logger.debug("Entered simple_php_dec()")
    # check if the req keys are available
    if not all(obj in json_enc for obj in list_of_json_obj):
        raise ValueError("Req keys in json_enc string not found")

    # get hex data from json
    enc_data = json.loads(json_enc)
    hex_et = enc_data["et"]
    hex_iv = enc_data["iv"]

    # covert hex to bytes
    bin_et = binascii.unhexlify(hex_et)  # will be in base64
    bin_iv = binascii.unhexlify(hex_iv)

    # create decrypt cipher obj
    decrypt_cipher = AES.new(key, aes_mode, bin_iv)

    # decrypt data
    dec_data = decrypt_cipher.decrypt(bin_et)
    logger.debug(f"dec_data: {dec_data}")

    # Unpad to get plain Text
    dec_data_unpadded = unpad(dec_data, AES.block_size)
    plain_text = dec_data_unpadded.decode("utf-8")
    return plain_text


def simple_php_dec_call():
    json_enc = '{"iv":"e81645bdec1800898d1feed7998c0194","et":"af1e6905500dd05a6f8c7461f7742985"}'
    list_of_json_obj = ["iv", "et"]
    aes_mode = AES.MODE_CBC

    key = "garchomp"
    bin_str_key = key.encode("utf-8")
    bin_str_key_pad = bin_str_key + b"\0" * (32 - len(bin_str_key))

    hex_key = binascii.hexlify(bin_str_key_pad)
    correct_bin_key = (
        b"67617263686f6d70000000000000000000000000000000000000000000000000"
    )
    # check if the keys are matching with PHP
    assert (
        hex_key == correct_bin_key
    ), f"hex key is {hex_key}\n, required is {correct_bin_key}\n"

    bin_key = bin_str_key_pad

    try:
        dt = simple_php_dec(
            json_enc=json_enc,
            key=bin_key,
            aes_mode=aes_mode,
            list_of_json_obj=list_of_json_obj,
        )
    except ValueError as e:
        logger.error(e)
        print("Exiting...")
        sys.exit(1)

    # logger.debug(f"Decrypted data: {dt}")
    assert dt == "pokemon", logger.error(
        f"Decrypted data is not pokemon, it is {dt}"
    )
    logger.info("DEC WORKS!!")


def main():
    simple_php_dec_call()


if __name__ == "__main__":
    main()
