
from dataclasses import astuple
from struct import pack, unpack
from zlib import adler32

import lzss

from .types import PrelinkedKernelHeader

LZSS_HEAD_SIZE = 0x180
LZSS_STRUCT_SIZE = 0x18
LZSS_PADDING_SIZE = LZSS_HEAD_SIZE - LZSS_STRUCT_SIZE
LZSS_PADDING_DATA = b'\x00' * LZSS_PADDING_SIZE
LZSS_SIGNATURE = b'comp'
LZSS_COMPRESSTYPE = b'lzss'

def compress(data: bytes, kASLRSupported: bool) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError

    if not isinstance(kASLRSupported, bool):
        raise TypeError

    compressedData = lzss.compress(data)

    header = PrelinkedKernelHeader(
        LZSS_SIGNATURE,
        LZSS_COMPRESSTYPE,
        adler32(data),
        len(data),
        len(compressedData),
        1 if kASLRSupported else 0
    )

    headerPacked = pack('>4s4s4I', *astuple(header))
    newData = headerPacked + LZSS_PADDING_DATA + compressedData
    return newData


def decompress(data: bytes) -> bytes:
    header = PrelinkedKernelHeader(*unpack('>4s4s4I', data[:LZSS_STRUCT_SIZE]))

    if not isinstance(header.signature, bytes):
        raise TypeError

    if not isinstance(header.compressType, bytes):
        raise TypeError

    if not isinstance(header.adler32, int):
        raise TypeError

    if not isinstance(header.uncompressedSize, int):
        raise TypeError

    if not isinstance(header.compressedSize, int):
        raise TypeError

    if not isinstance(header.prelinkVersion, int):
        raise TypeError

    if header.signature != LZSS_SIGNATURE:
        raise ValueError(f'Unknown signature. Expected {LZSS_SIGNATURE}, got {header.signature}!')

    if header.compressType != LZSS_COMPRESSTYPE:
        raise ValueError(f'Unknown compress type. Expected {LZSS_COMPRESSTYPE}, got {header.compressType}!')

    realData = data[LZSS_HEAD_SIZE:]
    realDataSize = len(realData)

    if realDataSize != header.compressedSize:
        raise ValueError(f'Size mismatch! Expected {header.compressedSize}, got {realDataSize}!')

    uncompressedData = lzss.decompress(realData)
    uncompressedDataSize = len(uncompressedData)

    if uncompressedDataSize != header.uncompressedSize:
        raise ValueError(f'Size mismatch! Expected {header.uncompressedSize}, got {uncompressedDataSize}!')

    checksum = adler32(uncompressedData)

    if checksum != header.adler32:
        raise ValueError('Adler32 mismatch!')

    if header.prelinkVersion not in (0, 1):
        raise ValueError(f'Unknown prelinkVersion! Expected 0 or 1, got {header.prelinkVersion}!')

    return uncompressedData
