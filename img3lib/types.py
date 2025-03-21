
from dataclasses import dataclass


@dataclass
class img3tag:
    magic: bytes
    totalSize: int
    dataSize: int
    data: bytes
    padding: bytes


@dataclass
class img3:
    magic: bytes
    fullSize: int
    sizeNoPack: int
    sigCheckArea: int
    ident: bytes
    tags: list


@dataclass
class kbag:
    cryptState: int
    aesType: int
    iv: bytes
    key: bytes


# https://github.com/apple-oss-distributions/kext_tools/blob/main/kernelcache.h
# prelinkVersion value >= 1 means KASLR supported (iOS 6+)
@dataclass
class PrelinkedKernelHeader:
    signature: bytes
    compressType: bytes
    adler32: int
    uncompressedSize: int
    compressedSize: int
    prelinkVersion: int
