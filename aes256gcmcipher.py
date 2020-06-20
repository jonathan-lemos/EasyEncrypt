from typing import Iterable, Union, Dict, List
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import b64
from cipher import Cipher as Cph
from bufferedreader import BufferedReader
import base64


class Aes256GcmCipher(Cph):
    def __init__(self, iv: bytes):
        self.__iv = iv

    def key_length(self) -> int:
        return 32

    def encrypt(self, key: bytes, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        encryptor = Cipher(algorithms.AES(key), modes.GCM(self.__iv, tag=None, min_tag_length=16),
                           default_backend()).encryptor()

        with BufferedReader(input) as br:
            for block in br.chunks(16 * 1024):
                yield encryptor.update(block)

            yield encryptor.finalize()
            yield encryptor.tag

    def decrypt(self, key: bytes, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        decryptor = Cipher(algorithms.AES(key), modes.GCM(self.__iv, tag=None, min_tag_length=16),
                           default_backend()).decryptor()

        buf = b''
        with BufferedReader(input) as br:
            for block in br.chunks():
                if len(block) < 16:
                    buf += block
                    if len(block) >= 32:
                        yield decryptor.update(buf[:-16])
                        buf = buf[-16:]
                else:
                    yield decryptor.update(buf)
                    buf = block

        if len(buf) < 16:
            raise ValueError("This encrypted data is not long enough to hold an authentication tag.")

        rem, tag = buf[:-16], buf[-16:]
        yield decryptor.update(rem)
        try:
            yield decryptor.finalize_with_tag(tag)
        except InvalidTag as e:
            raise ValueError(
                "The authentication tag did not match. Most likely the key is incorrect or the data is corrupt.") from e

    def serialize(self) -> Dict[str, Union[str, int, bool, None, Dict, List]]:
        return {
            "algorithm": "aes-256-gcm",
            "iv": b64.encode(self.__iv)
        }

    @staticmethod
    def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]) -> "Aes256GcmCipher":
        ret = Aes256GcmCipher(b'')

        base_keys = set(ret.serialize().keys())
        if not base_keys.issubset(props.keys()):
            raise ValueError(f"The properties dict is missing required keys {base_keys - props.keys()}")

        if props["algorithm"] != ret.serialize()["algorithm"]:
            raise ValueError(f"Expected an algo field of 'aes-256-gcm'. Got '{ret.serialize()['algo']}.")

        ret.__iv = b64.decode(props["iv"])

        return ret
