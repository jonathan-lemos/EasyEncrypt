from typing import Any, Dict, List, Optional, Union
import b64

from ciphers.aeadcipher import AeadCipher
from Crypto.Cipher import ChaCha20_Poly1305
from securerandom import rand_unique_bytes


class ChaCha20Poly1305Cipher(AeadCipher):
    def __init__(self, nonce: Optional[bytes] = None):
        if nonce is None:
            nonce = rand_unique_bytes(12)
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes.")
        self.nonce = nonce

    def _get_encryptor(self, key: bytes) -> Any:
        return ChaCha20_Poly1305.new(key=key, nonce=self.nonce)

    def _get_decryptor(self, key: bytes) -> Any:
        return self._get_encryptor(key)

    def _mac_len(self) -> int:
        return 16

    def key_length(self) -> int:
        return 32

    def serialize(self) -> Dict[str, Union[str, int, bool, None, Dict, List]]:
        return {
            "algorithm": "chacha20-poly1305",
            "nonce": b64.encode(self.nonce)
        }

    @staticmethod
    def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]) -> "ChaCha20Poly1305Cipher":
        ret = ChaCha20Poly1305Cipher()

        base_keys = set(ret.serialize().keys())
        if not base_keys.issubset(props.keys()):
            raise ValueError(f"The properties dict is missing required keys {base_keys - props.keys()}")

        if props["algorithm"] != ret.serialize()["algorithm"]:
            raise ValueError(f"Expected an algo field of 'aes-256-gcm'. Got '{ret.serialize()['algo']}.")

        ret.nonce = b64.decode(props["nonce"])
        if len(ret.nonce) != 12:
            raise ValueError(f"Decoded nonce must be 12 bytes")

        return ret