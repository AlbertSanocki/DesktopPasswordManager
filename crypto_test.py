"""Crypto module test"""
from crypto import Crypto

TEXT = 'Test for test 123!@#'
crypto = Crypto('pin')

def test_enrypt_decrypt():
    """Test of encrypt and decrypt methods"""
    encrypted_text = crypto.encrypt(TEXT)
    decrypted_text = crypto.decrypt(encrypted_text)
    assert encrypted_text != 'Test for test 123!@#'
    assert len(encrypted_text) == 120
    assert decrypted_text  == TEXT
