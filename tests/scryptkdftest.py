from kdfs.scryptkdf import ScryptKdf
import unittest


class TestScryptKdf(unittest.TestCase):
    def test_serialize_deserialize(self):
        tmp = ScryptKdf.sensitive()
        tmp.salt = bytes(range(32))
        tmp2 = tmp.serialize()
        tmp3 = ScryptKdf.deserialize(tmp2)

        self.assertEqual(tmp.salt, tmp3.salt)
        self.assertEqual(tmp.log2_n, tmp3.log2_n)
        self.assertEqual(tmp.r, tmp3.r)
        self.assertEqual(tmp.p, tmp3.p)

    def test_derive(self):
        tmp = ScryptKdf.sensitive()
        tmp.salt = bytes(range(32))

        res = tmp.derive("abrakadabra", 24)
        self.assertEqual(len(res), 24)
