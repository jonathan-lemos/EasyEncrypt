from abc import ABC, abstractmethod
from typing import Iterable, Union, Dict, List

from aes256gcmcipher import Aes256GcmCipher
from securerandom import rand_bytes


class Cipher(ABC):
    @abstractmethod
    def encrypt(self, key: bytes, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        pass

    @abstractmethod
    def decrypt(self, key: bytes, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        pass

    @abstractmethod
    def key_length(self) -> int:
        pass

    @abstractmethod
    def serialize(self) -> Dict[str, Union[str, int, bool, None, Dict, List]]:
        pass

    @staticmethod
    @abstractmethod
    def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]) -> "Cipher":
        pass


__cipher_switcher = {
    "aes-256-gcm": Aes256GcmCipher.deserialize
}


def supported_ciphers() -> Iterable[str]:
    return __cipher_switcher.keys()


def default_cipher() -> Cipher:
    return Aes256GcmCipher(rand_bytes(32))


def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]):
    if "algorithm" not in props:
        raise ValueError("Cipher dictionary must include 'algorithm' field.")

    if props["algorithm"] not in supported_ciphers():
        raise ValueError(f"The given cipher '{props['algorithm']}' is not supported.")

    return __cipher_switcher[props["algorithm"]](props)
