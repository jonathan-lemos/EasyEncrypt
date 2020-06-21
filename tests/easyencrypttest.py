import easyencrypt
import unittest
from kdfs.argon2kdf import Argon2Kdf
from ciphers.aes256gcmcipher import Aes256GcmCipher
from tests.symmetric import symmetric_test_env


class TestEasyEncryptDecrypt(unittest.TestCase):
    def test_encrypt_decrypt(self):
        password = "hunter2"
        kdf = Argon2Kdf.fast()
        cipher = Aes256GcmCipher(b'0' * 16)

        enc, dec = symmetric_test_env(lambda x: easyencrypt.encrypt(password, kdf, cipher, x),
                                      lambda x: easyencrypt.decrypt(password, x))

        self.assertEqual(enc, dec)
