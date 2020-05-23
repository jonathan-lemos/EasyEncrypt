from Argon2Params import Argon2Params
import Aes256Gcm
from typing import Iterable
from Random import rand_bytes
import itertools


def encrypt(password: str, input: Iterable[bytes], sensitive: bool = True):
    a2 = Argon2Params.sensitive() if sensitive else Argon2Params.fast()
    iv = rand_bytes(32)
    key = a2.derive(password, 32)

    yield a2.serialize()
    yield len(iv).to_bytes(2, "big")
    yield iv
    yield from Aes256Gcm.encrypt(key, iv, input)


def decrypt(password: str, input: Iterable[bytes]):
    buf = b''
    it = iter(input)

    def get(n: int):
        nonlocal buf
        nonlocal it

        while len(buf) < n:
            tmp = next(it, None)
            if tmp is None:
                return None
            buf += tmp

        ret, buf = buf[:n], buf[n:]

        return ret

    a2_head = b''
    while isinstance(a2 := Argon2Params.deserialize(a2_head), int):
        tmp = get(a2 - len(a2_head))
        if tmp is None:
            raise ValueError("The given data is not long enough to be EasyEncrypted data.")
        a2_head += tmp


    iv_len = get(2)
    if iv_len is None:
        raise ValueError("The given data is not long enough to be EasyEncrypted data.")
    iv_len = int.from_bytes(iv_len, "big")
    if iv_len < 0:
        raise ValueError("The given data is not valid EasyEncrypted data (iv_len cannot be < 0).")

    iv = get(iv_len)
    if iv is None:
        raise ValueError("The given data is not valid EasyEncrypted data (not enough bytes to fill iv).")

    key = a2.derive(password, 32)

    yield from Aes256Gcm.decrypt(key, iv, itertools.chain([buf], it))
