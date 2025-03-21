
from pathlib import Path


def readBytesFromPath(path: Path) -> bytes:
    if not isinstance(path, Path):
        raise TypeError
    
    if not path.is_file():
        raise ValueError(f'{path} is not a file!')
    
    return path.read_bytes()


def writeBytesToPath(path: Path, data: bytes) -> int:
    if not isinstance(path, Path):
        raise TypeError
    
    if not isinstance(data, bytes):
        raise TypeError

    if path.is_file():
        raise FileExistsError(f'{path} already exists!')
    
    return path.write_bytes(data)
