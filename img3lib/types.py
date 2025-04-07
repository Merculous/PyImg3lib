
from dataclasses import dataclass
from io import BytesIO


@dataclass
class img3tag:
    magic: BytesIO
    totalSize: int
    dataSize: int
    data: BytesIO
    padding: BytesIO


@dataclass
class img3:
    magic: BytesIO
    fullSize: int
    sizeNoPack: int
    sigCheckArea: int
    ident: BytesIO
    tags: list[img3tag]


@dataclass
class kbag:
    cryptState: int
    aesType: int
    iv: BytesIO
    key: BytesIO


# https://github.com/apple-oss-distributions/kext_tools/blob/main/kernelcache.h
# prelinkVersion value >= 1 means KASLR supported (iOS 6+)
@dataclass
class PrelinkedKernelHeader:
    signature: BytesIO
    compressType: BytesIO
    adler32: int
    uncompressedSize: int
    compressedSize: int
    prelinkVersion: int
