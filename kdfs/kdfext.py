from typing import Dict, List, Union, Iterable, Tuple, Optional
from kdfs.argon2kdf import Argon2Kdf
from kdfs.scryptkdf import ScryptKdf
from kdfs.kdf import Kdf
from math import floor, log2
import re
import log


def __parse_memory_unit(val: str) -> int:
    if re.fullmatch(r"\d+", val):
        return int(val)

    mat = re.match(r"^(\d+(?:\.\d+)?)\s*([a-z]+)$")
    if not mat:
        raise ValueError(f"Expected a size. Got {val}")

    size, unit = mat.group(1), mat.group(2)
    size = float(size)

    units = {
        "g": 1024 * 1024 * 1024,
        "gb": 1000 * 1000 * 1000,
        "gib": 1024 * 1024 * 1024,
        "m": 1024 * 1024,
        "mb": 1000 * 1000,
        "mib": 1024 * 1024,
        "k": 1024,
        "kb": 1000,
        "kib": 1024,
        "b": 1
    }

    if unit not in units:
        log.warning(f"Unrecognized unit '{unit}'; assuming bytes. Supported units: [{', '.join(sorted(units.keys()))}]")
        unit = "b"

    return int(round(size * units[unit]))


def __parse_argon2(name: str, params: List[Tuple[str, Optional[str]]]) -> Argon2Kdf:
    ret = Argon2Kdf.sensitive()

    if name == "argon2":
        name = "argon2id"
    ret.type = Argon2Kdf.str_to_type(name)

    for key, value in params:
        if key == "fast":
            ret = Argon2Kdf.fast()
        elif key == "sensitive":
            ret = Argon2Kdf.sensitive()
        elif value is None:
            log.warning(f"Key '{key}' is unrecognized for argon2 and/or needs an associated value.")
        elif key in {"time_cost", "n", "n_iterations"}:
            vint = int(value)
            ret.time_cost = vint
        elif key in {"mem_cost", "mem", "m", "memory"}:
            mint = __parse_memory_unit(value) // 1024
            ret.memory_cost = mint
        elif key in {"salt", "s"}:
            ret.salt = bytes(value, "utf-8")
        elif key in {"parallelism", "para", "p"}:
            pint = int(value)
            ret.parallelism = pint
        else:
            log.warning(f"Unrecognized key '{key}' in params string.")

    return ret


def __parse_scrypt(name: str, params: List[Tuple[str, Optional[str]]]) -> ScryptKdf:
    ret = ScryptKdf.sensitive()

    if name != "scrypt":
        raise ValueError(f"Name must be 'scrypt'. Was '{name}'")

    for key, value in params:
        if key == "fast":
            ret = ScryptKdf.fast()
        elif key == "sensitive":
            ret = ScryptKdf.sensitive()
        elif value is None:
            log.warning(f"Key '{key}' is unrecognized for scrypt and/or needs an associated value.")
        elif key in {"log2n", "log2_n"}:
            ret.log2_n = int(value)
        elif key in {"n"}:
            ret.log2_n = int(floor(log2(float(value))))
        elif key in {"r"}:
            ret.r = int(value)
        elif key in {"p"}:
            ret.p = int(value)
        else:
            log.warning(f"Unrecognized key '{key}' in params string.")

    return ret



__kdf_switcher = {
    "argon2": (Argon2Kdf.deserialize, __parse_argon2),
    "argon2id": (Argon2Kdf.deserialize, __parse_argon2),
    "argon2d": (Argon2Kdf.deserialize, __parse_argon2),
    "argon2i": (Argon2Kdf.deserialize, __parse_argon2),
    "scrypt": (ScryptKdf.deserialize, __parse_scrypt)
}


def supported_kdfs() -> Iterable[str]:
    return __kdf_switcher.keys()


def default_kdf() -> Kdf:
    return Argon2Kdf.sensitive()


def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]) -> Kdf:
    if "algorithm" not in props:
        raise ValueError("Kdf dictionary must include 'algorithm' field.")

    if props["algorithm"] not in supported_kdfs():
        raise ValueError(f"The given kdf algorithm '{props['algorithm']}' is not supported.")

    return __kdf_switcher[props["algorithm"]][0](props)


def from_option_string(s: str) -> Kdf:
    s = s.strip().lower()

    name = re.sub(r":.*$", "", s)
    params = re.sub(r"^.*?:", "", s) if ":" in s else ""

    par = [tuple(z) if len(z) == 2 else (z[0], None) for z in map(lambda x: x.strip().split("=") if "=" in x else [], params.split(",") if "," in params else [])]

    if name not in __kdf_switcher:
        raise ValueError(f"The given kdf algorithm '{name}' is not supported.")

    return __kdf_switcher[name][1](name, par)
