from abc import ABC, abstractmethod
from typing import Iterable, Union


class Cipher(ABC):
    @abstractmethod
    def encrypt(self, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        pass

    @abstractmethod
    def decrypt(self, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        pass