
import struct

from hashlib import sha1

from Crypto.Cipher import AES

from .errors import DataSizeMismatch


def readBinaryFile(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def writeBinaryFile(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)


def doAES(encrypt: bool, aes_type: str | int, data: bytes , iv: str | bytes, key: str | bytes) -> bytes:
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


def getSHA1(data: bytes) -> str:
    return sha1(data).hexdigest()


def getBufferAtIndex(data: bytes, index: int, length: int) -> bytes:
    buffer = data[index:index+length]

    buffer_len = len(buffer)

    if buffer_len != length:
        raise DataSizeMismatch(f'Expected {length}, got {buffer_len}!')

    return buffer


def formatData(format: str, data: bytes, pack: bool = True) -> bytes | tuple:
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


def isAligned(n: int, alignment: int) -> bool:
    return n % alignment == 0
