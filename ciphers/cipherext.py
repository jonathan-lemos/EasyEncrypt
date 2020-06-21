import re

from ciphers.aes256gcmcipher import Aes256GcmCipher
from ciphers.chacha20poly1305cipher import ChaCha20Poly1305Cipher
from ciphers.cipher import Cipher
from securerandom import rand_bytes
from typing import Dict, Iterable, List, Union, Optional, Tuple
import log
import sys


def __parse_aes256gcm(name: str, params: List[Tuple[str, Optional[str]]]) -> Aes256GcmCipher:
    ret = Aes256GcmCipher(rand_bytes(32))

    if name not in {"aes256", "aes256gcm", "aes-256", "aes-256-gcm", "aes256-gcm"}:
        raise ValueError(f"Given name '{name}' is not aes-256-gcm")

    for key, value in params:
        if key in {"iv", "nonce"}:
            if value is None:
                value = ''
            ret = Aes256GcmCipher(bytes(value, 'utf-8'))
        else:
            log.warning(f"Unrecognized key '{key}' in params string.")

    return ret


def __parse_chacha20(name: str, params: List[Tuple[str, Optional[str]]]) -> ChaCha20Poly1305Cipher:
    ret = ChaCha20Poly1305Cipher(rand_bytes(12))

    if name not in {"chacha20poly1305", "chacha20-poly1305"}:
        raise ValueError(f"Given name '{name}' is not aes-256-gcm")

    for key, value in params:
        if key in {"iv", "nonce"}:
            if value is None:
                value = ''
            byt = bytes(value, 'utf-8')
            if len(byt) != 12:
                log.error("Nonce must be 12 bytes")
                sys.exit(0)
            ret = Aes256GcmCipher(bytes(value, 'utf-8'))
        else:
            log.warning(f"Unrecognized key '{key}' in params string.")

    return ret


__cipher_switcher = {
    "aes256": (Aes256GcmCipher.deserialize, __parse_aes256gcm),
    "aes256gcm": (Aes256GcmCipher.deserialize, __parse_aes256gcm),
    "aes-256": (Aes256GcmCipher.deserialize, __parse_aes256gcm),
    "aes-256-gcm": (Aes256GcmCipher.deserialize, __parse_aes256gcm),
    "aes256-gcm": (Aes256GcmCipher.deserialize, __parse_aes256gcm),
    "chacha20-poly1305": (ChaCha20Poly1305Cipher.deserialize, __parse_chacha20),
    "chacha20poly1305": (ChaCha20Poly1305Cipher.deserialize, __parse_chacha20),
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

    return __cipher_switcher[props["algorithm"]][0](props)


def from_option_string(s: str) -> Cipher:
    s = s.strip().lower()

    name = re.sub(r":.*$", "", s)
    params = re.sub(r"^.*?:", "", s) if ":" in s else ""

    par = [tuple(z) if len(z) == 2 else (z[0], None) for z in map(lambda x: x.strip().split("=") if "=" in x else [], params.split(",") if "," in params else [])]

    if name not in __cipher_switcher:
        raise ValueError(f"The given kdf algorithm '{name}' is not supported.")

    return __cipher_switcher[name][1](name, par)
