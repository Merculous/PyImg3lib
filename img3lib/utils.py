
from plistlib import loads
from typing import Any


def isNumberAligned(n: int, align: int) -> bool:
    return n % align == 0


def alignNumber(n: int, align: int) -> int:
    alignedSize = n

    while not isNumberAligned(alignedSize, align):
        alignedSize += 1

    return alignedSize


def initPadding(size: int) -> bytes:
    return b'\x00' * size


def appendPaddingToData(padSize: int, data: bytes) -> bytes:
    dataSize = len(data)

    paddedSize = alignNumber(dataSize, padSize)
    paddingSize = paddedSize - dataSize
    paddingData = data + initPadding(paddingSize)

    return paddingData


def readPlistData(data: bytes) -> Any:
    return loads(data)
