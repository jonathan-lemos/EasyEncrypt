# easy-encrypt
A script that symmetrically encrypts or decrypts input.
## Table of Contents
* [Dependencies](#dependencies)
* [Installing and running](#installing-and-running)
* [Arguments](#arguments)
    * [Memory units](#memory-units)
    * [`[action]`](#action)
    * [`-c, --cipher`](#-c---cipher)
        * [`aes-256-gcm`](#aes-256-gcm)
        * [`chacha20-poly1305`](#chacha20-poly1305)
    * [`-in, --input`](#-in---input)
    * [`-k, --kdf`](#-k---kdf)
        * [`argon2`](#argon2-argon2id-argon2i-argon2d)
        * [`scrypt`](#scrypt)
    * [`-out, --output`](#-out---output)
        

## Dependencies
* [Python 3.8+](https://www.python.org/downloads/)
    * [PyCryptodome 3.9.4+](https://pypi.org/project/pycryptodome/)

## Installing and running
The easiest way to get the project is through [git](https://git-scm.com/)
```shell script
git clone https://github.com/jonathan-lemos/easy-encrypt.git
```

To run the script:
```shell script
python main.py [action] [arguments?...]
```

## Arguments
The script's behavior is primarily controlled through the following command-line arguments.

### Memory units
Some of the options below take a memory unit.

| Unit   | Value                  |
| ------ | :--------------------- |
| b      | 1 byte                 |
| kb     | 10<sup>3</sup> bytes   |
| k      | 2<sup>10</sup> bytes   |
| kib    | 2<sup>10</sup> bytes   |
| mb     | 10<sup>6</sup> bytes   |
| m      | 2<sup>20</sup> bytes   |
| mib    | 2<sup>20</sup> bytes   |
| gb     | 10<sup>9</sup> bytes   |
| g      | 2<sup>30</sup> bytes   |
| gib    | 2<sup>30</sup> bytes   |

### `[action]`
The action to perform. This is the only required command-line argument.

| `[action]`| description                           |
| :-------: | :------------------------------------ |
|`enc`      | Encrypts data                         |
|`dec`      | Decrypts data                         |
|`kdfs`     | Lists the kdfs the script can use.    |
|`ciphers`  | Lists the ciphers the script can use. |

### `-c, --cipher`
The symmetric cipher to encrypt with along with its options.
If this option is not specified, the script encrypt with `aes-256-gcm` and a randomly-generated 32-byte nonce.

This option is not used when decrypting.

This option is given in the format
```shell script
--cipher=algo:param1=value1,param2,param3=value3,...
```
or the following if no options are required
```shell script
--cipher=algo
```

For example, to encrypt with `chacha20-poly1305`:
```shell script
python main.py --cipher=chacha20-poly1305
```

To encrypt with `aes-256-gcm` and a 16-byte nonce, use
```shell script
python main.py --cipher=aes-256-gcm:nonce-len=16
```

The cipher encrypts/decrypts your data. The available ciphers and their options are given below:

#### `aes-256-gcm`
The default cipher.
This is one of the most heavily studied symmetric ciphers which should theoretically minimize the chance of any weaknesses.
Fast on processors with the AES-NI instruction set (most Intel and AMD processors from 2013+).

| Option              | Description                                                                        |
| :-----------------: | :--------------------------------------------------------------------------------- |
| `iv-len, nonce-len` | Generate a random nonce of the given length. The value must be a positive integer. |
| `iv, nonce`         | Use the given base64 string as a nonce.                                            |

#### `chacha20-poly1305`
An alternative cipher if you don't trust AES. Faster on processors without AES-NI and also not susceptible to cache-timing attacks like AES.

| Option             | Description |
| :-----:             | :---------  |
| `iv, nonce`         | Use the given base64 string as a nonce. The decoded nonce must be 12 bytes. |

### `-in, --input`
Specifies an input file. By default, input is read through stdin.

### `-k, --kdf`
The key derivation function (KDF) turns your password into a key usable by your cipher.
The (kdfs) and their options are given below:

#### `argon2, argon2id, argon2i, argon2d`
The default kdf.
Highly secure against dedicated hardware due to its memory requirements, but less battle-tested than other kdfs.
Argon2 comes with several variations:

| Option                       | Description                                                                                           |
| :--------------------------: | :---------------------------------------------------------------------------------------------------- |
| `argon2, argon2id`           | The default. A tradeoff between the two below algorithms, giving a lesser amount of both resistances. |
| `argon2i`                    | Uses data-independent memory access, making it invulnerable to side-channel timing attacks.           |
| `n, n_iterations, time_cost` | Uses data-dependent memory access, making it more resistant to time-memory tradeoff attacks.          |


The options available to all of the above kdfs are as follows.

| Option                       | Description                                                                                                                                                       |
| :--------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sensitive`                  | The default. Equivalent to `n=12,m=2gib,p=2`                                                                                                                      |
| `fast`                       | A faster but still decently secure variant. Equivalent to `n=2,m=256mib,p=1`                                                                                      |
| `n, n_iterations, time_cost` | The number of iterations performed by the algorithm. The time taken scales linearly with this value. Must be a positive integer.                                  |
| `m, mem, memory, mem_cost`   | The amount of memory used by the algorithm. Must be a positive real number and a [memory unit](#memory-units). Real numbers are rounded down to the nearest byte. |
| `p, para, parallelism`       | The number of threads the algorithm uses. Must be a positive integer.                                                                                             |
| `s, salt`                    | The salt to use. Must be a base64 string.                                                                                                                         |
| `sl, salt-len`               | Generate a random salt of the given length. Must be a positive integer.                                                                                           |

#### `scrypt`
An alternative to Argon2 that is more battle-tested, but less secure against brute-force attacks.

| Option                       | Description                                                                                                                                                                          |
| :--------------------------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sensitive`                  | The default. Equivalent to `log2n=20,r=8,p=1`                                                                                                                                        |
| `fast`                       | A faster but still decently secure variant. Equivalent to `log2n=14,r=8,p=1`                                                                                                         |
| `log2n, log2_n`              | The log2 of the number of iterations performed by the algorithm. The time taken scales exponentially with this value. Must be a positive integer.                                    |
| `n`                          | The log2 of the number of iterations performed by the algorithm. The time taken scales linearly with this value. Must be a positive integer. Rounded down to the nearest power of 2. |
| `r`                          | Controls the amount of memory used by the algorithm. Time taken and memory used scale linearly with it. Must be a positive integer.                                                  |
| `p`                          | The number of threads the algorithm uses. CPU usage scaled linearly with it. Must be a positive integer.                                                                             |
| `s, salt`                    | The salt to use. Must be a base64 string.                                                                                                                                            |
| `sl, salt-len`               | Generate a random salt of the given length. Must be a positive integer.                                                                                                              |

### `-out, --output`
Specifies an output file. By default, input is written to stdout.

### `-pw, --password-env-var`
Specifies the environment variable that contains the password. By default this is `EASYENCRYPT_PW`.
If this environment variable is not set, the passphrase is read through the terminal if stdin is a tty, otherwise the script exits.

### `-v, --verbose`
Displays more information to stderr.

## File format

| Byte numbers             | Description                                       |
| :----------------------: | :------------------------------------------------ |
| [0, 2)                   | The magic bytes `b'EZ'`                           |
| [2, 6)                   | The length of the header dictionary.              |
| [6, 6 + header_length)   | The [JSON header dictionary](#header-dictionary). |
| [6 + header_length, end) | The encrypted data.                               |

### Header dictionary
```
{
  "kdf": {
    "algorithm": "the name of the kdf algorithm",
    // the rest of the kdf's properties
  },
  "cipher": {
    "algorithm": "the name of the cipher algorithm",
    // the rest of the cipher's properties
  },
}
```
