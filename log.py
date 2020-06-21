import sys


def __color(s: str, n: int) -> str:
    if sys.stderr.isatty():
        return f"\033[{n}m{s}\033[m"
    else:
        return s


def warning(s):
    sys.stderr.write(__color(f"Warning: {s}", 33))


def error(s):
    sys.stderr.write(__color(f"Error: {s}", 31))
