from typing import Iterable
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def encrypt(key: bytes, iv: bytes, input: Iterable[bytes]):
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag=None, min_tag_length=16), default_backend()).encryptor()

    for block in input:
        yield encryptor.update(block)

    yield encryptor.finalize()
    yield encryptor.tag


def decrypt(key: bytes, iv: bytes, input: Iterable[bytes]):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag=None, min_tag_length=16), default_backend()).decryptor()

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
        raise ValueError("The authentication tag did not match. Most likely the data is corrupt or the key is incorrect.") from e

