from typing import Iterable, Union
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cipher import Cipher as Cph
from bufferedreader import BufferedReader


class Aes256GcmCipher(Cph):
    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        self.__key, self.__iv = key, iv

    def encrypt(self, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        encryptor = Cipher(algorithms.AES(self.__key), modes.GCM(self.__iv, tag=None, min_tag_length=16),
                           default_backend()).encryptor()

        with BufferedReader as br:
            for block in br.chunks(16 * 1024):
                yield encryptor.update(block)

            yield encryptor.finalize()
            yield encryptor.tag

    def decrypt(self, input: Union[bytes, Iterable[bytes], str]) -> Iterable[bytes]:
        decryptor = Cipher(algorithms.AES(self.__key), modes.GCM(self.__iv, tag=None, min_tag_length=16),
                           default_backend()).decryptor()

        buf = b''
        for block in input:
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
