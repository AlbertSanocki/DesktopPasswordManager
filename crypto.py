"""Crypto module necessary for encryption and decryption of passwords stored in the database"""
import hashlib
from base64 import b64encode
from cryptography.fernet import Fernet

class Crypto:
    """Crypto class used
    for encryption and decryption with fernet from cryptography"""
    def __init__(self, pin: str):
        self.pin = Crypto.create_key(pin)
        self.fernet = Fernet(self.pin)

    @staticmethod
    def create_key(pin):
        """Preparing the key. Key needs to be base64 32 byte object"""
        token = hashlib.md5(pin.encode('utf8')).hexdigest()
        token = b64encode(token.encode('utf8'))
        return token

    def encrypt(self, password):
        """the encrypt method returns the encrypted password as str"""
        return self.fernet.encrypt(password.encode('utf8')).decode('utf8')

    def decrypt(self, password):
        """the decrypt method returns the decrypted password as str"""
        return self.fernet.decrypt(password.encode('utf8')).decode('utf8')
