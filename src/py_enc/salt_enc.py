import json
import binascii
import base64
from Crypto.Cipher import AES
from helpers import salt_helpers
from Crypto.Util.Padding import pad


def encrypt_aes256_cbc(data: str, password: str, iterations: int) -> str:
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
    json_base_64_encode = base64.b64encode(json_ed.encode("utf-8"))
    json_base_64_encode_str = str(json_base_64_encode, "utf-8")
    return json_base_64_encode_str


def salt_python_enc_call():
    data = "pokemon"
    password = "pikachu"
    iterations = 100
    json_et = encrypt_aes256_cbc(data, password, iterations)
    return json_et


def main():
    json_et = salt_python_enc_call()
    print(f"json_et: {json_et}")


if __name__ == "__main__":
    main()
