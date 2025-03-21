
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15


def doSHA1(buffer: bytes) -> bytes:
    return SHA1.new(buffer).digest()


def doAES(encrypt, aes_type, data, iv, key):
    if isinstance(aes_type, str):
        aes_type = int(aes_type)

    if isinstance(iv, str):
        iv = bytes.fromhex(iv)

    if isinstance(key, str):
        key = bytes.fromhex(key)

    iv_len = len(iv)
    key_len = len(key)

    if iv_len != 16:
        raise Exception(f'Bad iv length: {iv_len}')

    if key_len < 16:
        raise Exception(f'Bag key length: {key_len}')

    if aes_type == 128:
        if key_len > 16:
            key = key[16:]

    elif aes_type == 192:
        if key_len > 24:
            key = key[24:]

    elif aes_type == 256:
        if key_len > 32:
            key = key[32:]

    else:
        raise Exception(f'Unknown AES type: {aes_type}')

    cipher = AES.new(key, AES.MODE_CBC, iv)

    if encrypt is True:
        data = cipher.encrypt(data)

    elif encrypt is False:
        data = cipher.decrypt(data)

    else:
        raise Exception(f'Unknown mode: {encrypt}')

    return data


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


def pad(padSize: int, data: bytes) -> bytes:
    if not isinstance(padSize, int):
        raise TypeError

    if not isinstance(data, bytes):
        raise TypeError

    dataSize = len(data)
    paddedSize = padNumber(dataSize, padSize)
    paddingSize = paddedSize - dataSize
    data += b'\x00' * paddingSize
    return data


def doRSACheck(key, sig, data):
    scheme = pkcs1_15.new(key)
    dataSHA1 = SHA1.new(data)
    valid = False

    try:
        scheme.verify(dataSHA1, sig)
        valid = True
    except (ValueError, TypeError):
        pass

    return valid
