
from zlib import adler32

from Crypto.Cipher import AES


def readBinaryFile(path):
    with open(path, 'rb') as f:
        return f.read()


def writeBinaryFile(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def aes(mode, data, iv, key):
    iv = bytes.fromhex(iv)
    key = bytes.fromhex(key)

    iv_len = len(iv)
    key_len = len(key)

    if iv_len == 32:
        # AES 256
        iv = iv[:16]

    if key_len == 64:
        # AES 256
        key = key[32:]

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
