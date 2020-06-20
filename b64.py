import base64


def encode(arg: bytes) -> str:
    return str(base64.b64encode(arg), "utf-8")


def decode(arg: str) -> bytes:
    return base64.b64decode(arg, validate=True)
