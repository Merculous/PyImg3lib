
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pkcs1_15

AES_SIZES = {
    128: 16,
    192: 24,
    256: 32
}

def doAES(encrypt: bool, aesType: int, data: bytes, iv: bytes, key: bytes) -> bytes:
    if not isinstance(encrypt, bool):
        raise TypeError(f'Encrypt must be of type: {bool}')

    if not isinstance(aesType, int):
        raise TypeError(f'aesType must be of type: {int}')

    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    if not isinstance(iv, bytes):
        raise TypeError(f'IV must be of type: {bytes}')

    if not isinstance(key, bytes):
        raise TypeError(f'Key must be of type: {bytes}')

    if aesType not in AES_SIZES:
        raise ValueError(f'Unknown aes type: {aesType}!')

    if not data:
        raise ValueError('No data to read!')

    ivSize = len(iv)
    keySize = len(key)

    if ivSize != 16:
        raise ValueError('IV must be of size: 16')

    if keySize not in AES_SIZES.values():
        raise ValueError('Key is not of size: 16, 24, or 32!')

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    buffer = b''

    if encrypt:
        buffer = cipher.encrypt(data)
    else:
        buffer = cipher.decrypt(data)

    return buffer


def doRSACheck(rsaKey: RsaKey, rsaSignedData: bytes, sha1Data: bytes) -> bool:
    if not isinstance(rsaKey, RsaKey):
        raise TypeError(f'rsaKey must be of type: {RsaKey}')

    if not isinstance(rsaSignedData, bytes):
        raise TypeError(f'rsaSignedData must be of type: {bytes}')

    if not isinstance(sha1Data, bytes):
        raise TypeError(f'sha1Data must be of type: {bytes}')

    if not rsaSignedData:
        raise ValueError('No data to read!')

    if not sha1Data:
        raise ValueError('No data to read!')

    scheme = pkcs1_15.new(rsaKey)
    dataSHA1 = SHA1.new(sha1Data)
    valid = False

    try:
        scheme.verify(dataSHA1, rsaSignedData)
    except ValueError:
        pass
    except Exception:
        raise
    else:
        valid = True

    return valid
