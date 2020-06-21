from abc import ABC, abstractmethod

from bufferedreader import BufferedReader
from ciphers.cipher import Cipher
from typing import Any, Iterable, Union


class AeadCipher(Cipher, ABC):
    @abstractmethod
    def _get_encryptor(self, key: bytes) -> Any:
        pass

    @abstractmethod
    def _get_decryptor(self, key: bytes) -> Any:
        pass

    @abstractmethod
    def _mac_len(self) -> int:
        pass

    def encrypt(self, key: bytes, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        encryptor = self._get_encryptor(key)

        with BufferedReader(input) as br:
            for block in br.chunks(16 * 1024):
                yield encryptor.encrypt(block)
            dig = encryptor.digest()
            assert len(dig) == self._mac_len()
            yield dig

    def decrypt(self, key: bytes, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        decryptor = self._get_decryptor(key)
        ml = self._mac_len()

        buf = b''
        with BufferedReader(input) as br:
            for block in br.chunks():
                if len(block) < ml:
                    buf += block
                    if len(block) >= 2 * ml:
                        yield decryptor.decrypt(buf[:-ml])
                        buf = buf[-ml:]
                else:
                    yield decryptor.decrypt(buf)
                    buf = block

        if len(buf) < ml:
            raise ValueError("This encrypted data is not long enough to hold an authentication tag.")

        rem, tag = buf[:-ml], buf[-ml:]
        yield decryptor.decrypt(rem)
        decryptor.verify(tag)
