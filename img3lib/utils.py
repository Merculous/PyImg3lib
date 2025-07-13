
from pathlib import Path
from plistlib import loads
from typing import Any


def isAligned(n: int, align: int) -> bool:
    if not isinstance(n, int):
        raise TypeError(f'N must be of type: {int}')

    if not isinstance(align, int):
        raise TypeError(f'Align must be of type: {int}')

    return n % align == 0


def padNumber(n: int, align: int) -> int:
    if not isinstance(n, int):
        raise TypeError(f'N must be of type: {int}')

    if not isinstance(align, int):
        raise TypeError(f'Align must be of type: {int}')

    paddedSize = n

    while not isAligned(paddedSize, align):
        paddedSize += 1

    return paddedSize


def pad(padSize: int, data: bytearray) -> bytearray:
    if not isinstance(padSize, int):
        raise TypeError(f'PadSize must be of type: {int}')

    if not isinstance(data, bytearray):
        raise TypeError(f'Data must be of type: {bytearray}')

    if not data:
        raise ValueError('No data to read!')

    dataSize = len(data)

    paddedSize = padNumber(dataSize, padSize)
    paddingSize = paddedSize - dataSize
    paddingData = b'\x00' * paddingSize
    data.extend(paddingData)

    return data


def readPlist(path: Path) -> Any:
    if not isinstance(path, Path):
        raise TypeError(f'Path must be of type: {Path}')

    if not path.is_file():
        raise ValueError(f'{path} is not a file!')

    return loads(path.read_bytes())
