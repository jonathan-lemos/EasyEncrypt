from kdfs.argon2kdf import Argon2Kdf
import unittest


class TestArgon2Kdf(unittest.TestCase):
    def test_serialize_deserialize(self):
        tmp = Argon2Kdf.sensitive()
        tmp.salt = bytes(range(32))
        tmp2 = tmp.serialize()
        tmp3 = Argon2Kdf.deserialize(tmp2)

        self.assertEqual(tmp.salt, tmp3.salt)
        self.assertEqual(tmp.version, tmp3.version)
        self.assertEqual(tmp.type, tmp3.type)
        self.assertEqual(tmp.time_cost, tmp3.time_cost)
        self.assertEqual(tmp.memory_cost, tmp3.memory_cost)
        self.assertEqual(tmp.type, tmp3.type)
        self.assertEqual(tmp.version, tmp3.version)

    def test_derive(self):
        tmp = Argon2Kdf.sensitive()
        tmp.salt = bytes(range(32))

        res = tmp.derive("abrakadabra", 24)
        self.assertEqual(len(res), 24)
