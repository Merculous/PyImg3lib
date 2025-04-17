
from io import SEEK_END, SEEK_SET, BytesIO
from pathlib import Path
from plistlib import loads
from typing import Any

from binpatch.io import getSizeOfIOStream


def isAligned(n: int, align: int) -> bool:
    if not isinstance(n, int):
        raise TypeError

    if not isinstance(align, int):
        raise TypeError

    return n % align == 0


def padNumber(n: int, align: int) -> int:
    if not isinstance(n, int):
        raise TypeError

    if not isinstance(align, int):
        raise TypeError

    paddedSize = n

    while not isAligned(paddedSize, align):
        paddedSize += 1

    return paddedSize


def pad(padSize: int, data: BytesIO) -> BytesIO:
    if not isinstance(padSize, int):
        raise TypeError

    if not isinstance(data, BytesIO):
        raise TypeError

    dataSize = getSizeOfIOStream(data)

    if dataSize == 0:
        raise ValueError('No data to read!')

    paddedSize = padNumber(dataSize, padSize)
    paddingSize = paddedSize - dataSize

    data.seek(0, SEEK_END)
    data.write(b'\x00' * paddingSize)
    data.seek(0, SEEK_SET)

    return data


def readPlist(path: Path) -> Any:
    if not isinstance(path, Path):
        raise TypeError

    if not path.is_file():
        raise ValueError(f'{path} is not a file!')

    return loads(path.read_bytes())
