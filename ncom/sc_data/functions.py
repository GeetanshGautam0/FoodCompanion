import hashlib, rsa, sys
from typing import cast, Tuple
from dataclasses import dataclass
from . import constants as sc_const
from . import struct as sc_struct


def memoize(func):
    cache = {}

    def wrapper(*args, **kwargs):
        aks = f'{args}{kwargs}'
        if aks in cache:
            return cache[aks]
        else:
            res = func(*args, **kwargs)
            cache[aks] = res

            return res

    return wrapper


GET_BYTES    = lambda data: (
    data if isinstance(data, bytes) else
    data.encode() if isinstance(data, str) else
    str(data).encode()
)

GET_CHECKSUM = lambda data: hashlib.sha256(GET_BYTES(data)).hexdigest()


def GET_RSA_KEYS() -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
    return rsa.newkeys(sc_const.MSG.NG_RSA_KEY_SIZE)


class LoggingLevel:
    ERROR = 0
    WARN  = 1
    INFO  = 2
    DEBUG = 3


@dataclass
class Block:
    prev_hash:      str
    time_stamp:     int
    data:           bytes
    hash:           str


class BlockChain:
    def __init__(self) -> None:
        # TODO: Implement.
        pass


@dataclass
class LogFile:
    file_struct: sc_struct.File
    hash_file:   sc_struct.File
    data:        BlockChain


def LOG(fout: LogFile, logging_level: int, data: str) -> None:
    # TODO: implement.
    #   1. Log w/ some way of detecting tampering (parity/block-chain?)
    #   2. Add time stamps
    #   3. The logs do not need to be human-readable; make a GUI to display logs.

    pass


def STDOUT(data: str, __pr: str = '') -> int:
    return sys.stdout.write(f'[FCS]{f" <{__pr}>" if len(__pr) else ""} {data}\n')


def STDERR(data: str, __pr: str = '') -> int:
    return sys.stderr.write(f'[FCS]{f" <{__pr}>" if len(__pr) else ""} {data}\n')


def _rsa_block_encrypt(message: bytes, pubKey: rsa.PublicKey) -> bytes:
    block_size = sc_const.RSABlockSize(sc_const.MSG.NG_RSA_KEY_SIZE)
    STDOUT(f"RSABlockEncrypt<{block_size=}; L={len(message)}>", "RSAUtil @ _rsa_block_encrypt")

    assert isinstance(message, bytes)
    assert isinstance(pubKey, rsa.PublicKey)

    sections = []

    for bi in range(blocks := (len(message) // block_size)):
        STDOUT(f"Block<{bi + 1}/{blocks} @ BS{block_size}>", "RSAUtil @ _rsa_block_encrypt")
        sect = message[(bi * block_size): ((bi + 1) * block_size):]

        sections.append(rsa.encrypt(sect, pubKey))

    if (rem := len(message) % block_size) > 0:
        STDOUT(f"Rem<{rem}>", "RSAUtil @ _rsa_block_encrypt")
        sect = message[blocks * block_size:(blocks * block_size) + rem]
        sections.append(rsa.encrypt(sect, pubKey))

    else:
        STDOUT(f"NRem", "RSAUtil @ _rsa_block_encrypt")

    return b''.join(sections)


def _rsa_block_decrypt(message: bytes, privKey: rsa.PrivateKey) -> bytes:
    block_size = sc_const.MSG.NG_RSA_KEY_SIZE // 8
    STDOUT(f"RSABlockDecrypt<{block_size=}; L={len(message)}>", "RSAUtil @ _rsa_block_decrypt")

    assert isinstance(message, bytes)
    assert isinstance(privKey, rsa.PrivateKey)

    sections = []

    for bi in range(blocks := (len(message) // block_size)):
        STDOUT(f"Block<{bi + 1}/{blocks} @ BS{block_size}>", "RSAUtil @ _rsa_block_decrypt")
        sect = message[(bi * block_size): ((bi + 1) * block_size):]

        sections.append(rsa.decrypt(sect, privKey))

    if (rem := len(message) % block_size) > 0:
        STDOUT(f"Rem<{rem}>", "RSAUtil @ _rsa_block_decrypt")
        sect = message[blocks * block_size:(blocks * block_size) + rem]
        sections.append(rsa.decrypt(sect, privKey))

    else:
        STDOUT(f"NRem", "RSAUtil @ _rsa_block_decrypt")

    return b''.join(sections)


ENCRYPT_DATA = lambda data, public_key: rsa.encrypt(GET_BYTES(data), public_key)
DECRYPT_DATA = lambda data, private_key: rsa.decrypt(data, private_key)

BLOCK_ENCRYPT_DATA = lambda data, public_key: _rsa_block_encrypt(GET_BYTES(data), public_key)
BLOCK_DECRYPT_DATA = lambda data, private_key: _rsa_block_decrypt(data, private_key)
