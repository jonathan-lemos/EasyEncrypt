import secrets


def rand_bytes(n: int):
    return secrets.token_bytes(n)
