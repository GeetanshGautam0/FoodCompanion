import hashlib, rsa
from typing import cast, Tuple
from . import constants as sc_const


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
    with rsa.newkeys(512) as (pb, pr):
        yield (
            cast(rsa.PublicKey, pb).save_pkcs1(sc_const.HDR.RSA_KEY_TYPE),
            cast(rsa.PrivateKey, pr).save_pkcs1(sc_const.HDR.RSA_KEY_TYPE),
        )


ENCRYPT_DATA = lambda data, public_key: rsa.encrypt(GET_BYTES(data), public_key)
DECRYPT_DATA = lambda data, private_key: rsa.decrypt(data, private_key)
