
from struct import pack, unpack
from zlib import adler32

import lzss
from binpatch.utils import getBufferAtIndex

from .types import PrelinkedKernelHeader
from .utils import initPadding

LZSS_HEAD_SIZE = 0x180
LZSS_STRUCT_SIZE = 0x18
LZSS_PADDING_SIZE = LZSS_HEAD_SIZE - LZSS_STRUCT_SIZE
LZSS_SIGNATURE = b'comp'
LZSS_COMPRESSTYPE = b'lzss'

MACHO_MAGIC = b'\xce\xfa\xed\xfe'


def initPrelinkedKernelHeader() -> PrelinkedKernelHeader:
    return PrelinkedKernelHeader(b'', b'', 0, 0, 0, 0)


def parsePrelinkedKernelHeader(data: bytes) -> PrelinkedKernelHeader:
    dataSize = len(data)

    if dataSize < LZSS_STRUCT_SIZE:
        raise ValueError(f'Data buffer must be at least {LZSS_STRUCT_SIZE} bytes!')

    headData = getBufferAtIndex(data, 0, LZSS_STRUCT_SIZE)
    signature, compressType, adler32, uncompressedSize, compressedSize, prelinkVersion = unpack('>4s4s4I', headData)

    header = initPrelinkedKernelHeader()
    header.signature = signature
    header.compressType = compressType
    header.adler32 = adler32
    header.uncompressedSize = uncompressedSize
    header.compressedSize = compressedSize
    header.prelinkVersion = prelinkVersion

    return header


def compress(data: bytes, kASLRSupported: bool) -> bytes:
    dataSize = len(data)
    compressedData = lzss.compress(data)

    header = (
        LZSS_SIGNATURE,
        LZSS_COMPRESSTYPE,
        adler32(data),
        dataSize,
        len(compressedData),
        1 if kASLRSupported else 0
    )

    headerPacked = pack('>4s4s4I', *header) + initPadding(LZSS_PADDING_SIZE) + compressedData
    return headerPacked


def decompress(data: bytes) -> bytes:
    header = parsePrelinkedKernelHeader(data)

    if header.signature != LZSS_SIGNATURE:
        raise ValueError(f'Unknown signature. Expected {LZSS_SIGNATURE.decode()}, got {header.signature.decode()}!')

    if header.compressType != LZSS_COMPRESSTYPE:
        raise ValueError(f'Unknown compress type. Expected {LZSS_COMPRESSTYPE.decode()}, got {header.compressType.decode()}!')

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
