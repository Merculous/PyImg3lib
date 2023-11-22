
from zlib import adler32
from Crypto.Cipher import AES


def aes_decrypt(data, iv, key):
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def getKernelChecksum(data):
    return adler32(data)
