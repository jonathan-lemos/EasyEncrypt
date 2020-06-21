import hashlib
from typing import Dict, Union, List, Optional

import b64
from kdfs.kdf import Kdf
from securerandom import rand_bytes


class ScryptKdf(Kdf):
    @staticmethod
    def fast():
        return ScryptKdf(14, 8, 1)

    @staticmethod
    def sensitive():
        return ScryptKdf(20, 8, 1)

    def __init__(self, log2_n: int, r: int, p: int, salt: Optional[bytes] = None):
        self.log2_n, self.r, self.p = log2_n, r, p
        self.salt = salt if salt is not None else rand_bytes(32)

    def derive(self, password: str, out_len: int) -> bytes:
        return hashlib.scrypt(bytes(password, "utf-8"),
                              salt=self.salt,
                              n=2 ** self.log2_n,
                              r=self.r,
                              p=self.p,
                              maxmem=2 ** 31 - 1,
                              dklen=out_len)

    def serialize(self) -> Dict[str, Union[str, int, bool, None, Dict, List]]:
        return {
            "algorithm": "scrypt",
            "log2_n": self.log2_n,
            "r": self.r,
            "p": self.p,
            "salt": b64.encode(self.salt)
        }

    @staticmethod
    def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]) -> "ScryptKdf":
        ret = ScryptKdf.sensitive()

        base_keys = set(ret.serialize().keys())
        if not base_keys.issubset(props.keys()):
            raise ValueError(f"The properties dict is missing required keys {base_keys - props.keys()}")

        if props["algorithm"] != "scrypt":
            raise ValueError(f"The algorithm field must be 'scrypt'. Was '{props['algorithm']}'")

        ret.log2_n = props["log2_n"]
        ret.r = props["r"]
        ret.p = props["p"]
        ret.salt = b64.decode(props["salt"])

        return ret
