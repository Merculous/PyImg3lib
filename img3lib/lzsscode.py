
from struct import pack, unpack
from zlib import adler32

import lzss
from binpatch.utils import getBufferAtIndex

from .types import PrelinkedKernelHeader

LZSS_HEAD_SIZE = 0x180
LZSS_STRUCT_SIZE = 0x18
LZSS_PADDING_SIZE = LZSS_HEAD_SIZE - LZSS_STRUCT_SIZE
LZSS_SIGNATURE = b'comp'
LZSS_COMPRESSTYPE = b'lzss'


def initPrelinkedKernelHeader() -> PrelinkedKernelHeader:
    return PrelinkedKernelHeader(b'', b'', 0, 0, 0, 0)


def parsePrelinkedKernelHeader(data: bytes) -> PrelinkedKernelHeader:
    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    dataSize = len(data)

    if dataSize < LZSS_STRUCT_SIZE:
        raise ValueError(f'Data buffer must be of size: {LZSS_STRUCT_SIZE}!')

    headerData = getBufferAtIndex(data, 0, LZSS_STRUCT_SIZE)
    signature, compressType, adler32, uncompressedSize, compressedSize, prelinkVersion = unpack('>4s4s4I', headerData)

    header = initPrelinkedKernelHeader()
    header.signature = signature
    header.compressType = compressType
    header.adler32 = adler32
    header.uncompressedSize = uncompressedSize
    header.compressedSize = compressedSize
    header.prelinkVersion = prelinkVersion

    return header


def createLZSSHeaderPadding() -> bytes:
    return b'\x00' * LZSS_PADDING_SIZE


def compress(data: bytes, kASLRSupported: bool) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    if not isinstance(kASLRSupported, bool):
        raise TypeError(f'kASLRSupported must be of type: {bool}')

    dataSize = len(data)

    if not data:
        raise ValueError('No data to read!')

    uncompressedData = data
    compressedData = lzss.compress(uncompressedData)

    header = (
        LZSS_SIGNATURE,
        LZSS_COMPRESSTYPE,
        adler32(uncompressedData),
        dataSize,
        len(compressedData),
        1 if kASLRSupported else 0
    )

    headerPacked = pack('>4s4s4I', *header) + createLZSSHeaderPadding() + compressedData
    return headerPacked


def decompress(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')
    
    if not data:
        raise ValueError('No data to read!')

    headerData = getBufferAtIndex(data, 0, LZSS_STRUCT_SIZE)
    header = parsePrelinkedKernelHeader(headerData)

    if not isinstance(header.signature, bytes):
        raise TypeError(f'Signature must be of type: {bytes}')

    if not isinstance(header.compressType, bytes):
        raise TypeError(f'CompressType must be of type: {bytes}')

    if not isinstance(header.adler32, int):
        raise TypeError(f'Adler32 must be of type: {int}')

    if not isinstance(header.uncompressedSize, int):
        raise TypeError(f'uncompressedSize must be of type {int}')

    if not isinstance(header.compressedSize, int):
        raise TypeError(f'compressedSize must be of type: {int}')

    if not isinstance(header.prelinkVersion, int):
        raise TypeError(f'prelinkVersion must be of type: {int}')

    if header.signature != LZSS_SIGNATURE:
        raise ValueError(f'Unknown signature. Expected {LZSS_SIGNATURE}, got {header.signature}!')

    if header.compressType != LZSS_COMPRESSTYPE:
        raise ValueError(f'Unknown compress type. Expected {LZSS_COMPRESSTYPE}, got {header.compressType}!')

    realData = getBufferAtIndex(data, LZSS_HEAD_SIZE, header.compressedSize)
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
