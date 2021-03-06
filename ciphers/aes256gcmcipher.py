from typing import Union, Dict, List, Any, Optional
from Crypto.Cipher import AES

import b64
from ciphers.aeadcipher import AeadCipher

from securerandom import rand_unique_bytes


class Aes256GcmCipher(AeadCipher):
    def __init__(self, nonce: Optional[bytes] = None):
        if nonce is None:
            nonce = rand_unique_bytes(32)
        self.nonce = nonce

    def _get_encryptor(self, key: bytes) -> Any:
        return AES.new(key, AES.MODE_GCM, nonce=self.nonce, mac_len=self._mac_len())

    def _get_decryptor(self, key: bytes) -> Any:
        return self._get_encryptor(key)

    def _mac_len(self) -> int:
        return 16

    def key_length(self) -> int:
        return 32

    def serialize(self) -> Dict[str, Union[str, int, bool, None, Dict, List]]:
        return {
            "algorithm": "aes-256-gcm",
            "nonce": b64.encode(self.nonce)
        }

    @staticmethod
    def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]) -> "Aes256GcmCipher":
        ret = Aes256GcmCipher(b'')

        base_keys = set(ret.serialize().keys())
        if not base_keys.issubset(props.keys()):
            raise ValueError(f"The properties dict is missing required keys {base_keys - props.keys()}")

        if props["algorithm"] != ret.serialize()["algorithm"]:
            raise ValueError(f"Expected an algo field of 'aes-256-gcm'. Got '{ret.serialize()['algo']}.")

        ret.nonce = b64.decode(props["nonce"])

        return ret
