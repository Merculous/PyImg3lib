
import struct

from hashlib import sha1
from zlib import adler32

from Crypto.Cipher import AES


def readBinaryFile(path):
    with open(path, 'rb') as f:
        return f.read()


def writeBinaryFile(path, data):
    with open(path, 'wb') as f:
        f.write(data)


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


def getKernelChecksum(data):
    return adler32(data)


def getSHA1(data):
    return sha1(data).hexdigest()


def getBufferAtIndex(data, index, length):
    buffer = data[index:index+length]

    buffer_len = len(buffer)

    if buffer_len != length:
        raise Exception(f'Buffer length mismatch! Got {buffer_len}')

    return buffer


def formatData(format, data, pack=True):
    formatted_data = None

    # Use "*" if we are given a list/tuple
    unpack_var = False

    if isinstance(data, list) or isinstance(data, tuple):
        unpack_var = True

    if pack is True:
        if unpack_var:
            formatted_data = struct.pack(format, *data)
        else:
            formatted_data = struct.pack(format, data)

    elif pack is False:
        if unpack_var:
            formatted_data = struct.unpack(format, *data)
        else:
            formatted_data = struct.unpack(format, data)
    else:
        raise ValueError(f'Expected pack as bool, got: {type(pack)}')

    return formatted_data


def pad(padSize, data):
    data_len = len(data)

    padded_len = data_len

    while padded_len % padSize != 0:
        padded_len += 1

    padded_len = padded_len - data_len

    padding = b'\x00' * padded_len

    padded = data + padding

    return padded
