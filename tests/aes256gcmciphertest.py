from aes256gcmcipher import Aes256GcmCipher
import unittest


class TestAes256GcmCipher(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = bytes(range(32))
        iv = bytes(range(24))
        cipher = Aes256GcmCipher(iv)

        data_chunks = [bytes(range(i, 71 + i)) for i in range(6)]
        data_flat = b''.join(data_chunks)

        enc = list(cipher.encrypt(key, data_chunks))
        enc_flat = b''.join(enc)
        enc_processed = [enc_flat[i: i + 67] for i in range(0, len(enc_flat), 67)]

        dec = list(cipher.decrypt(key, filter(lambda x: x != b'', enc_processed)))

        self.assertEqual(data_flat, b''.join(dec))