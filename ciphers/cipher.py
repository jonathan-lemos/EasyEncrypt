from abc import ABC, abstractmethod
from typing import Iterable, Union, Dict, List

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
