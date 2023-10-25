"""Encrypt AES-256-CBC with salt for secret key generation

Encrypts a string using AES-256-CBC with salt for secret key generation

Usage:
    encrypt_aes256_cbc(data, password, iterations)
"""
import base64
import binascii
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from helpers import salt_helpers


def encrypt_aes256_cbc(data: str, password: str, iterations: int) -> str:
    """encryption function for AwS-256-CBC with salt for secret key generation

    Args:
        data(str): plaintext to be encrypted
        password(str): password
        iterations(int): number of iterations to be used in PBKDF2

    Returns:
        json_base_64_encode_str(str): json string with base64 encoded data
    """
    aes_mode = AES.MODE_CBC  # Only CBC mode is supported as of now
    # Create IV
    iv = AES.get_random_bytes(16)  # bytes

    # Create salt
    salt = AES.get_random_bytes(16)  # bytes

    # Create secret key
    secret_key = salt_helpers.generate_secret_key(
        salt, iterations, password
    )  # 32 Bytes

    # create cipher obj
    cipher = AES.new(secret_key, aes_mode, iv)

    # Encrypt data
    data_byte_str = data.encode("utf-8")
    pad_data = pad(data_byte_str, AES.block_size)
    enc_data = cipher.encrypt(pad_data)

    # Convert all values to hex
    hex_et = binascii.hexlify(enc_data)
    hex_iv = binascii.hexlify(iv)
    hex_salt = binascii.hexlify(salt)

    # Convert hex byte string to utf-8 string
    hex_str_et = str(hex_et, "utf-8")
    hex_str_iv = str(hex_iv, "utf-8")
    hex_str_salt = str(hex_salt, "utf-8")

    # Create JSON
    json_ed = json.dumps(
        {"et": hex_str_et, "iv": hex_str_iv, "salt": hex_str_salt}
    )
    # convert json to base64
    json_base_64_encode = base64.b64encode(json_ed.encode("utf-8"))
    # Convert byte string to utf-8 string
    json_base_64_encode_str = str(json_base_64_encode, "utf-8")
    return json_base_64_encode_str
