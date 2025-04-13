
from io import BytesIO

from binpatch.io import getSizeOfIOStream
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pkcs1_15

AES_SIZES = {
    128: 16,
    192: 24,
    256: 32
}

def doAES(encrypt: bool, aesType: int, data: BytesIO, iv: BytesIO, key: BytesIO) -> BytesIO:
    if not isinstance(encrypt, bool):
        raise TypeError

    if not isinstance(aesType, int):
        raise TypeError

    if not isinstance(data, BytesIO):
        raise TypeError

    if not isinstance(iv, BytesIO):
        raise TypeError

    if not isinstance(key, BytesIO):
        raise TypeError

    if aesType not in AES_SIZES:
        raise ValueError(f'Unknown aes type: {aesType}!')

    if getSizeOfIOStream(data) == 0:
        raise ValueError('No data to read!')

    ivSize = getSizeOfIOStream(iv)
    keySize = getSizeOfIOStream(key)

    if ivSize != 16:
        raise ValueError('IV must be of size: 16')

    if keySize not in AES_SIZES.values():
        raise ValueError('Key is not of size: 16, 24, or 32!')

    cipher = AES.new(key.getbuffer(), AES.MODE_CBC, iv=iv.getbuffer())
    buffer = BytesIO()

    if encrypt:
        buffer.write(cipher.encrypt(data.getbuffer()))
    else:
        buffer.write(cipher.decrypt(data.getbuffer()))

    return buffer

def doRSACheck(rsaKey: RsaKey, rsaSignedData: BytesIO, sha1Data: BytesIO) -> bool:
    if not isinstance(rsaKey, RsaKey):
        raise TypeError

    if not isinstance(rsaSignedData, BytesIO):
        raise TypeError

    if not isinstance(sha1Data, BytesIO):
        raise TypeError

    if getSizeOfIOStream(rsaSignedData) == 0:
        raise ValueError('No data to read!')

    if getSizeOfIOStream(sha1Data) == 0:
        raise ValueError('No data to read!')

    scheme = pkcs1_15.new(rsaKey)
    dataSHA1 = SHA1.new(sha1Data.getbuffer())
    valid = False

    try:
        scheme.verify(dataSHA1, rsaSignedData.getvalue())
    except ValueError:
        pass
    except Exception:
        raise
    else:
        valid = True

    return valid
