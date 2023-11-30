
from hashlib import sha1
from zlib import adler32

from Crypto.Cipher import AES


def readBinaryFile(path):
    with open(path, 'rb') as f:
        return f.read()


def writeBinaryFile(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def aes(mode, aes_type, data, iv, key):
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

    if mode == 'encrypt':
        data = cipher.encrypt(data)

    elif mode == 'decrypt':
        data = cipher.decrypt(data)

    else:
        raise Exception(f'Unknown mode: {mode}')

    return data


def getKernelChecksum(data):
    return adler32(data)


def getSHA1(data):
    return sha1(data).hexdigest()
