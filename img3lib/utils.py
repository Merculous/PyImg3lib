
from zlib import adler32

from Crypto.Cipher import AES


def readBinaryFile(path):
    with open(path, 'rb') as f:
        return f.read()


def writeBinaryFile(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def aes_decrypt(data, iv, key):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def getKernelChecksum(data):
    return adler32(data)
