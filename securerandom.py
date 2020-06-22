import secrets
import time


def rand_bytes(n: int):
    return secrets.token_bytes(n)


def rand_unique_bytes(n: int):
    t = int(time.time())
    if n < 8:
        return t.to_bytes(n, "big", signed=False)
    return t.to_bytes(8, "big", signed=False) + rand_bytes(n - 8)
