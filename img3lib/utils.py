
from io import SEEK_END, SEEK_SET, BytesIO

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


def doSHA1(buffer: BytesIO) -> BytesIO:
    if not isinstance(buffer, BytesIO):
        raise TypeError

    return BytesIO(SHA1.new(buffer.getbuffer()).digest())


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


def isAligned(n: int, align: int) -> bool:
    if not isinstance(n, int):
        raise TypeError

    if not isinstance(align, int):
        raise TypeError

    return n % align == 0


def padNumber(n: int, align: int) -> int:
    if not isinstance(n, int):
        raise TypeError

    if not isinstance(align, int):
        raise TypeError

    paddedSize = n

    while not isAligned(paddedSize, align):
        paddedSize += 1

    return paddedSize


def pad(padSize: int, data: BytesIO) -> BytesIO:
    if not isinstance(padSize, int):
        raise TypeError

    if not isinstance(data, BytesIO):
        raise TypeError

    dataSize = getSizeOfIOStream(data)
    paddedSize = padNumber(dataSize, padSize)
    paddingSize = paddedSize - dataSize

    data.seek(0, SEEK_END)
    data.write(b'\x00' * paddingSize)
    data.seek(0, SEEK_SET)

    return data


def doRSACheck(rsaKey: RsaKey, rsaSignedData: BytesIO, sha1Data: BytesIO) -> bool:
    scheme = pkcs1_15.new(rsaKey)
    dataSHA1 = SHA1.new(sha1Data.getvalue())
    valid = False

    try:
        scheme.verify(dataSHA1, rsaSignedData.getvalue())
        valid = True
    except (ValueError, TypeError):
        pass

    return valid
