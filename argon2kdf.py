import argon2
import b64
from typing import Optional, Dict, Union, List
from securerandom import rand_bytes
from kdf import Kdf



class Argon2Kdf(Kdf):
    @staticmethod
    def sensitive():
        return Argon2Kdf(12, 2 * 1024 * 1024, 8, argon2.Type.ID, rand_bytes(32))

    @staticmethod
    def fast():
        return Argon2Kdf(2, 256 * 1024, 2, argon2.Type.ID, rand_bytes(16))

    @staticmethod
    def __type_to_str(type: argon2.Type):
        return {
            argon2.Type.I: "argon2i",
            argon2.Type.D: "argon2d",
            argon2.Type.ID: "argon2id"
        }[type]

    @staticmethod
    def __str_to_type(type: str):
        try:
            return {
                "argon2i": argon2.Type.I,
                "argon2d": argon2.Type.D,
                "argon2id": argon2.Type.ID
            }[type]
        except KeyError:
            raise ValueError(f"Type must be one of ['argon2i', 'argon2d', 'argon2id'] (was '{type}')")

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
    def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]) -> "Argon2Kdf":
        ret = Argon2Kdf.sensitive()

        base_keys = set(ret.serialize().keys())
        if not base_keys.issubset(props.keys()):
            raise ValueError(f"The properties dict is missing required keys {base_keys - props.keys()}")

        ret.type = Argon2Kdf.__str_to_type(props["algorithm"])
        ret.version = props["version"]
        ret.time_cost = props["time_cost"]
        ret.memory_cost = props["memory_cost"]
        ret.parallelism = props["parallelism"]
        ret.salt = b64.decode(props["salt"])

        return ret

    def serialize(self) -> Dict[str, Union[str, int, bool, None, Dict, List]]:
        return {
            "algorithm": self.__type_to_str(self.type),
            "version": self.version,
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "salt": b64.encode(self.salt),
        }

    def derive(self, password: str, out_len: int) -> bytes:
        return argon2.low_level.hash_secret_raw(bytes(password, "utf-8"), self.salt, self.time_cost, self.memory_cost,
                                                self.parallelism, out_len, self.type, self.version)

    def __init__(self, time_cost: int, memory_cost: int, parallelism: int, type: argon2.Type,
                 salt: Optional[bytes] = None, version: int = argon2.low_level.ARGON2_VERSION):
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.type = type
        self.salt = salt if salt is not None else rand_bytes(32)
        self.version = version
