# easy-encrypt
A script that symmetrically encrypts or decrypts input.
## Table of Contents
* [Dependencies](#dependencies)
* [Installing and running](#installing-and-running)
* [Arguments](#arguments)
    * [`[action]`](#action)
    * [`-c, --cipher`](#-c---cipher)
        * [`aes-256-gcm`](#aes-256-gcm)
        * [`chacha20-poly1305`](#chacha20-poly1305)

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

The available ciphers and their options are given below:
#### `aes-256-gcm`
The default cipher.
This is one of the most heavily studied symmetric ciphers which should theoretically minimize the chance of any weaknesses.
Fast on processors with the AES-NI instruction set (most Intel and AMD CPUs from 2013+).

| Option             | Description |
| :-----:             | :---------  |
| `iv-len, nonce-len` | Generate a random nonce of the given length. The value must be an integer. |
| `iv, nonce`         | Use the given base64 string as a nonce. |

#### `chacha20-poly1305`
An alternative cipher if you don't trust AES. Faster on processors without AES-NI and also not susceptible to cache-timing attacks like AES.

| Option             | Description |
| :-----:             | :---------  |
| `iv, nonce`         | Use the given base64 string as a nonce. The decoded nonce must be 12 bytes. |


