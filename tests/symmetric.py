from typing import Callable, Iterable


def symmetric_test_env(encrypt: Callable[[Iterable[bytes]], Iterable[bytes]], decrypt: Callable[[Iterable[bytes]], Iterable[bytes]]):
    data_chunks = [bytes(range(i, 71 + i)) for i in range(6)]
    data_flat = b''.join(data_chunks)

    enc = list(encrypt(data_chunks))
    enc_flat = b''.join(enc)
    enc_processed = [enc_flat[i: i + 67] for i in range(0, len(enc_flat), 67)]

    dec = list(decrypt(filter(lambda x: x != b'', enc_processed)))
    return data_flat, b''.join(dec)
