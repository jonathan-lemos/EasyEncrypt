import EasyEncrypt
import argparse
import sys
import getpass
import os


def chunk(handle, size: int):
    while len(buf := handle.read(size)) != 0:
        yield buf


parser = argparse.ArgumentParser(
    description="Encrypts or decrypts input.")
parser.add_argument("action",
                    metavar="ACTION",
                    help="'enc' to encrypt, 'dec' to decrypt")
parser.add_argument("-f", "--fast",
                    action="store_false",
                    dest="sensitive",
                    help="use fast encryption, which takes less time but is weaker against brute-force attacks.",
                    default=True)
parser.add_argument("-in", "--input",
                    dest="input",
                    metavar="FILE",
                    help="a file to encrypt. by default input is taken from stdin",
                    default=None)
parser.add_argument("-out", "--output",
                    dest="output",
                    metavar="FILE",
                    help="the file to output to. by default output is written to stdout",
                    default=None)
parser.add_argument("-pw", "--password_environment_variable",
                    dest="pass_env",
                    metavar="ENV_VAR",
                    help="the name of the environment variable that contains the password. this is not the password itself",
                    default=None)
parser.add_argument("-s", "--sensitive",
                    action="store_true",
                    dest="sensitive",
                    help="use sensitive encryption, which takes longer but is stronger against brute-force attacks. this is the default",
                    default=True)
parser.add_argument("-v", "--verbose",
                    action="store_true",
                    dest="verbose",
                    help="display information to stderr",
                    default=False)

options = parser.parse_args()

if options.input is None:
    stdin = sys.stdin.buffer
else:
    stdin = open(options.input, "rb")

if options.output is None:
    stdout = sys.stdout.buffer
else:
    stdout = open(options.output, "wb")

if options.action is None:
    parser.print_help()
    sys.exit(0)

if options.action not in {"enc", "dec"}:
    parser.print_help()
    print(f"\nAction must be one of [enc, dec], was {options.action}.")
    sys.exit(0)

if options.pass_env is not None:
    password = os.environ.get(options.pass_env)
    if password is None:
        print(f"The given password environment variable {options.pass_env} was not set.")
        sys.exit(0)
else:
    password = getpass.getpass("Enter passphrase: ")


if options.action == "enc":
    for chunk in EasyEncrypt.encrypt(password, chunk(stdin, 1024 * 1024), options.sensitive):
        stdout.write(chunk)
elif options.action == "dec":
    for chunk in EasyEncrypt.decrypt(password, chunk(stdin, 1024 * 1024)):
        stdout.write(chunk)
