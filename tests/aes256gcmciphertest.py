from ciphers.aes256gcmcipher import Aes256GcmCipher
import unittest

from tests.symmetric import symmetric_test_env


class TestAes256GcmCipher(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = bytes(range(32))
        iv = bytes(range(24))
        cipher = Aes256GcmCipher(iv)

        enc, dec = symmetric_test_env(lambda x: cipher.encrypt(key, x), lambda x: cipher.decrypt(key, x))
        self.assertEqual(enc, dec)
