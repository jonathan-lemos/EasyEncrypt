import argon2
import hashlib
from typing import Optional
from Random import rand_bytes



def sha256hash(b: bytes):
    m = hashlib.sha256()
    m.update(b)
    return m.digest()


class Argon2Params:
    VERSION = 1

    @staticmethod
    def sensitive():
        return Argon2Params(12, 2 * 1024 * 1024, 8, argon2.Type.ID, rand_bytes(32))

    @staticmethod
    def fast():
        return Argon2Params(2, 256 * 1024, 2, argon2.Type.ID, rand_bytes(16))

    @staticmethod
    def __type_to_int(type: argon2.Type):
        return {
            argon2.Type.I: 0,
            argon2.Type.D: 1,
            argon2.Type.ID: 2
        }[type]

    @staticmethod
    def __int_to_type(type: int):
        try:
            return {
                0: argon2.Type.I,
                1: argon2.Type.D,
                2: argon2.Type.ID
            }[type]
        except KeyError:
            raise ValueError(f"The Argon2 type must be 0x0, 0x1, or 0x2 (was {hex(type)})")

    @staticmethod
    def deserialize(byt: bytes):
        b_ind = 0
        ret = Argon2Params.sensitive()

        def get(n: int):
            nonlocal byt, b_ind

            if len(byt) < n + b_ind:
                return None
            r = byt[b_ind:b_ind + n]

            b_ind += n
            return r

        lb = get(4)
        if not lb:
            return 4

        req_len = int.from_bytes(lb, "big")
        if req_len < 0:
            raise ValueError("The bytes do not represent a valid Argon2Params header (negative header length).")

        if len(byt) < req_len:
            return req_len

        lb = get(2)
        if not lb:
            raise ValueError(
                "The bytes do not represent a valid Argon2Params header (bytes shorter than required length).")

        if lb != b'EZ':
            raise ValueError("The bytes do not represent a valid Argon2Params header (magic header not detected).")

        lb = get(2)
        if not lb:
            raise ValueError(
                "The bytes do not represent a valid Argon2Params header (bytes shorter than required length).")

        ver = int.from_bytes(lb, "big")
        if ver != Argon2Params.VERSION:
            raise ValueError(
                f"The header has an invalid version field {hex(ver)}. Currently only header version 0x1 is supported.")

        lb = get(2)
        if not lb:
            raise ValueError(
                "The bytes do not represent a valid Argon2Params header (bytes shorter than required length).")

        ret.version = int.from_bytes(lb, "big")

        lb = get(2)
        if not lb:
            raise ValueError(
                "The bytes do not represent a valid Argon2Params header (bytes shorter than required length).")

        ret.time_cost = int.from_bytes(lb, "big")
        if ret.time_cost < 0:
            raise ValueError("The bytes do not represent a valid Argon2Params header (time_cost cannot be < 0).")

        lb = get(8)
        if not lb:
            raise ValueError(
                "The bytes do not represent a valid Argon2Params header (bytes shorter than required length).")

        ret.memory_cost = int.from_bytes(lb, "big")
        if ret.memory_cost < 0:
            raise ValueError("The bytes do not represent a valid Argon2Params header (memory_cost cannot be < 0).")

        lb = get(2)
        if not lb:
            raise ValueError(
                "The bytes do not represent a valid Argon2Params header (bytes shorter than required length).")

        ret.parallelism = int.from_bytes(lb, "big")
        if ret.parallelism < 0:
            raise ValueError("The bytes do not represent a valid Argon2Params header (parallelism cannot be < 0).")

        lb = get(2)
        if not lb:
            raise ValueError(
                "The bytes do not represent a valid Argon2Params header (bytes shorter than required length).")

        ret.type = Argon2Params.__int_to_type(int.from_bytes(lb, "big"))

        lb = get(2)
        if not lb:
            raise ValueError(
                "The bytes do not represent a valid Argon2Params header (bytes shorter than required length).")

        salt_len = int.from_bytes(lb, "big")

        ret.salt = get(salt_len)
        if not ret.salt:
            raise ValueError(
                f"The bytes do not represent a valid Argon2Params header (salt shorter than required length of {hex(salt)}).")

        checksum_exp = ret.checksum()
        checksum_bytes = byt[b_ind:b_ind + len(checksum_exp)]

        if len(checksum_exp) != len(checksum_bytes):
            raise ValueError(
                f"The bytes do not represent a valid Argon2Params header (checksum shorter than required length).")

        if checksum_exp != checksum_bytes:
            raise ValueError(f"The bytes do not represent a valid Argon2Params header (checksum mismatch).")

        return ret

    def checksum(self):
        return sha256hash(b''.join([
            Argon2Params.VERSION.to_bytes(2, "big"),
            self.version.to_bytes(2, "big"),
            self.time_cost.to_bytes(2, "big"),
            self.memory_cost.to_bytes(8, "big"),
            self.parallelism.to_bytes(2, "big"),
            Argon2Params.__type_to_int(self.type).to_bytes(2, "big"),
            self.salt
        ]))

    def serialize(self):
        base = b''.join([
            b'EZ',
            Argon2Params.VERSION.to_bytes(2, "big"),
            self.version.to_bytes(2, "big"),
            self.time_cost.to_bytes(2, "big"),
            self.memory_cost.to_bytes(8, "big"),
            self.parallelism.to_bytes(2, "big"),
            Argon2Params.__type_to_int(self.type).to_bytes(2, "big"),
            len(self.salt).to_bytes(2, "big"),
            self.salt
        ])
        h = self.checksum()

        return (len(base) + 4 + len(h)).to_bytes(4, "big") + base + h

    def derive(self, password: str, out_len: int):
        return argon2.low_level.hash_secret_raw(bytes(password, "utf-8"), self.salt, self.time_cost, self.memory_cost,
                                                self.parallelism, out_len, self.type)

    def __init__(self, time_cost: int, memory_cost: int, parallelism: int, type: argon2.Type,
                 salt: Optional[bytes] = None, version: int = argon2.low_level.ARGON2_VERSION):
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.type = type
        self.salt = salt if salt is not None else rand_bytes(32)
        self.version = version
