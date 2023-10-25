from py_dec import salt_dec


def test_decrypt_aes256_cbc_base():
    """test decrypt aes256 cbc"""
    json_base64_encoded = "eyJpdiI6ImNkNGQ0NTc0Zjk4Yzc5YmY3MDdmMGYwMjRkNDg5ZmUyIiwiZXQiOiI2ZjY4YmNjMDcxZjUwMjMwNGQwMDI4MDU2MDAyOGZlMiIsInNhbHQiOiJjZjk4ZjQ0MmMwNzdjZWQ1YWJlNTlkMTM0YThjMGVhMSJ9"
    list_of_json_obj = ["iv", "et", "salt"]
    password = "garchomp"
    iterations = 100
    assert (
        salt_dec.decrypt_aes256_cbc(
            json_base64_encoded=json_base64_encoded,
            password=password,
            iterations=iterations,
            list_of_json_obj=list_of_json_obj,
        )
        == "pokemon"
    )
