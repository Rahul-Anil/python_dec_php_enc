from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512


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
        ValueError:
            if the length of the secret key is not 32 bytes for AES-256
            if the length of the salt is not 16 bytes for AES-256
    """
    if len(salt) != 16:
        raise ValueError(
            f"Salt length is {len(salt)} bytes it should be 16 bytes"
        )
    secret_key = PBKDF2(
        password, salt, 32, iterations, None, hmac_hash_module=SHA512
    )  # 32 byte string is returned

    if len(secret_key) != 32:
        raise ValueError(
            "Secret key length is {len(secret_key)} bytes it should be 32 bytes"
        )
    return secret_key
