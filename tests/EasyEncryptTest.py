import easyencrypt
import unittest


class TestEasyEncryptDecrypt(unittest.TestCase):
    def test_encrypt_decrypt(self):
        password = "hunter2"

        data_chunks = [bytes(range(i, 71 + i)) for i in range(6)]
        data_flat = b''.join(data_chunks)

        enc = list(easyencrypt.encrypt(password, data_chunks, sensitive=False))
        enc_flat = b''.join(enc)
        enc_processed = [enc_flat[i: i + 67] for i in range(0, len(enc_flat), 67)]

        dec = list(easyencrypt.decrypt(password, filter(lambda x: x != b'', enc_processed)))

        self.assertEqual(data_flat, b''.join(dec))