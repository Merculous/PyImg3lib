
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pkcs1_15

from .utils import initPadding

AES_BLOCK_SIZE = AES.block_size
AES_SIZES = {
    128: 16,
    192: 24,
    256: 32
}

IV_DEFAULT_KEY = initPadding(AES_BLOCK_SIZE)

# Derived from here (Axi0mX and tihmstar) https://x.com/axi0mX/status/1594897094233710594?s=20
A4_GID_KEY = b''.fromhex('e77f3e9c5e6c00086aa7b68e58994a639cc360d6027c90b53eb8b3b015f72f56')
GID_KEY_SIZE = 32
SHSH_KEY_SIZE = 128


def doAES(encrypt: bool, aesType: int, data: bytes, iv: bytes, key: bytes) -> bytes:
    if aesType not in AES_SIZES:
        raise ValueError(f'Unknown aes type: {aesType}!')

    ivSize = len(iv)
    keySize = len(key)

    if ivSize != AES_BLOCK_SIZE:
        raise ValueError(f'IV must be of size: {AES_BLOCK_SIZE}')

    if keySize not in AES_SIZES.values():
        raise ValueError('Key is not of size: 16, 24, or 32!')

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    buffer = None

    if encrypt:
        buffer = cipher.encrypt(data)
    else:
        buffer = cipher.decrypt(data)

    return buffer


def doRSACheck(rsaKey: RsaKey, rsaSignedData: bytes, sha1Data: bytes) -> bool:
    scheme = pkcs1_15.new(rsaKey)
    dataSHA1 = SHA1.new(sha1Data)
    valid = False

    try:
        scheme.verify(dataSHA1, rsaSignedData)
    except ValueError:
        pass
    else:
        valid = True

    return valid
