import easyencrypt
import argparse
import sys
import getpass
import os
import ciphers.cipherext
import kdfs.kdfext
import log



def chunk(handle, size: int):
    while len(buf := handle.read(size)) != 0:
        yield buf


parser = argparse.ArgumentParser(
    description="Symmetrically encrypts or decrypts input.")
parser.add_argument("action",
                    metavar="ACTION",
                    help="'enc' to encrypt, 'dec' to decrypt. 'kdfs' to see a list of kdfs and their options. 'ciphers' to see a list of ciphers and their options")
parser.add_argument("-c", "--cipher",
                    dest="cipher",
                    metavar="CIPHER[:PARAMS]?",
                    help="the cipher to use along with any parameters",
                    default=None)
parser.add_argument("-in", "--input",
                    dest="input",
                    metavar="FILE",
                    help="a file to encrypt. by default input is taken from stdin",
                    default=None)
parser.add_argument("-k", "--kdf",
                    dest="kdf",
                    metavar="KDF[:PARAMS]?",
                    help="the key derivation function to use along with any parameters",
                    default=None)
parser.add_argument("-out", "--output",
                    dest="output",
                    metavar="FILE",
                    help="the file to output to. by default output is written to stdout",
                    default=None)
parser.add_argument("-pw", "--password-env-var",
                    dest="pass_env",
                    metavar="ENV_VAR",
                    help="the name of the environment variable that contains the password (default EASYENCRYPT_PW). this is not the password itself",
                    default=None)
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

if options.action not in {"enc", "dec", "kdfs", "ciphers"}:
    parser.print_help()
    print(f"\nAction must be one of [enc, dec, kdfs, ciphers], was {options.action}.")
    sys.exit(1)

if not stdin.isatty() and options.pass_env is None:
    options.pass_env = "EASYENCRYPT_PW"
if options.pass_env is not None:
    password = os.environ.get(options.pass_env)
    if password is None:
        print(f"\nThe password environment variable '{options.pass_env}' was not set.")
        sys.exit(1)
else:
    password = getpass.getpass("Enter passphrase: ")

if options.kdf is None:
    kdf = kdfs.kdfext.default_kdf()
else:
    kdf = kdfs.kdfext.from_option_string(options.kdf)

if options.cipher is None:
    cipher = ciphers.cipherext.default_cipher()
else:
    cipher = ciphers.cipherext.from_option_string(options.cipher)

try:
    if options.action == "enc":
        for chunk in easyencrypt.encrypt(password, kdf, cipher, chunk(stdin, 1024 * 1024)):
            stdout.write(chunk)
    elif options.action == "dec":
        for chunk in easyencrypt.decrypt(password, chunk(stdin, 1024 * 1024)):
            stdout.write(chunk)
except Exception as e:
    sys.stderr.write(str(e) + "\n")
