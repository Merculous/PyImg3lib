
from io import SEEK_END, SEEK_SET, BytesIO
from struct import pack, unpack
from zlib import adler32

import lzss
from binpatch.io import getSizeOfIOStream
from binpatch.utils import getBufferAtIndex

from .types import PrelinkedKernelHeader

LZSS_HEAD_SIZE = 0x180
LZSS_STRUCT_SIZE = 0x18
LZSS_PADDING_SIZE = LZSS_HEAD_SIZE - LZSS_STRUCT_SIZE
LZSS_SIGNATURE = BytesIO(b'comp')
LZSS_COMPRESSTYPE = BytesIO(b'lzss')


def initPrelinkedKernelHeader() -> PrelinkedKernelHeader:
    return PrelinkedKernelHeader(BytesIO(), BytesIO(), 0, 0, 0, 0)


def parsePrelinkedKernelHeader(data: BytesIO) -> PrelinkedKernelHeader:
    if not isinstance(data, BytesIO):
        raise TypeError

    dataSize = getSizeOfIOStream(data)

    if dataSize < LZSS_STRUCT_SIZE:
        raise ValueError(f'Data buffer must be of size: {LZSS_STRUCT_SIZE}!')

    headerData = getBufferAtIndex(data, 0, LZSS_STRUCT_SIZE)
    signature, compressType, adler32, uncompressedSize, compressedSize, prelinkVersion = unpack('>4s4s4I', headerData.getvalue())

    header = initPrelinkedKernelHeader()
    header.signature.seek(0, SEEK_SET)
    header.signature.write(signature)
    header.signature.seek(0, SEEK_SET)

    header.compressType.seek(0, SEEK_SET)
    header.compressType.write(compressType)
    header.compressType.seek(0, SEEK_SET)

    header.adler32 = adler32
    header.uncompressedSize = uncompressedSize
    header.compressedSize = compressedSize
    header.prelinkVersion = prelinkVersion

    return header


def createLZSSHeaderPadding() -> BytesIO:
    return BytesIO(b'\x00' * LZSS_PADDING_SIZE)


def compress(data: BytesIO, kASLRSupported: bool) -> BytesIO:
    if not isinstance(data, BytesIO):
        raise TypeError

    if not isinstance(kASLRSupported, bool):
        raise TypeError

    dataSize = getSizeOfIOStream(data)

    if dataSize == 0:
        raise ValueError('No data to read!')

    uncompressedData = data.getvalue()
    compressedData = BytesIO(lzss.compress(uncompressedData))

    header = (
        LZSS_SIGNATURE.getvalue(), # Ignore type warnings here
        LZSS_COMPRESSTYPE.getvalue(),
        adler32(uncompressedData),
        dataSize,
        getSizeOfIOStream(compressedData),
        1 if kASLRSupported else 0
    )

    headerPacked = BytesIO(pack('>4s4s4I', *header))
    headerPacked.seek(0, SEEK_END)
    headerPacked.write(createLZSSHeaderPadding().getvalue())
    headerPacked.write(compressedData.getvalue())
    headerPacked.seek(0, SEEK_SET)

    return headerPacked


def decompress(data: BytesIO) -> BytesIO:
    if not isinstance(data, BytesIO):
        raise TypeError
    
    if getSizeOfIOStream(data) == 0:
        raise ValueError('No data to read!')

    headerData = getBufferAtIndex(data, 0, LZSS_STRUCT_SIZE)
    header = parsePrelinkedKernelHeader(headerData)

    if not isinstance(header.signature, BytesIO):
        raise TypeError

    if not isinstance(header.compressType, BytesIO):
        raise TypeError

    if not isinstance(header.adler32, int):
        raise TypeError

    if not isinstance(header.uncompressedSize, int):
        raise TypeError

    if not isinstance(header.compressedSize, int):
        raise TypeError

    if not isinstance(header.prelinkVersion, int):
        raise TypeError

    if header.signature.getvalue() != LZSS_SIGNATURE.getvalue():
        raise ValueError(f'Unknown signature. Expected {LZSS_SIGNATURE.getvalue()}, got {header.signature.getvalue()}!')

    if header.compressType.getvalue() != LZSS_COMPRESSTYPE.getvalue():
        raise ValueError(f'Unknown compress type. Expected {LZSS_COMPRESSTYPE.getvalue()}, got {header.compressType.getvalue()}!')

    realData = getBufferAtIndex(data, LZSS_HEAD_SIZE, header.compressedSize).getvalue()
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

    return BytesIO(uncompressedData)
