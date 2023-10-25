from py_dec import salt_dec
from py_enc import salt_enc


def test_encrypt_aes256_cbc():
    """test for encrypt aes256 cbc"""
    data = "pokemon"
    password = "pikachu"
    iterations = 100
    # get encrypted json string
    json_et = salt_enc.encrypt_aes256_cbc(
        data=data, password=password, iterations=iterations
    )

    # pass data to decrypt_aes256_cbc() to see if it returns the same data
    assert (
        salt_dec.decrypt_aes256_cbc(
            json_base64_encoded=json_et,
            password=password,
            iterations=iterations,
            list_of_json_obj=["iv", "et", "salt"],
        )
        == data
    )
