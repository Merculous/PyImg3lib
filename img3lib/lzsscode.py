
import lzss
from zlib import adler32

from .const import LZSS_MODE_COMPRESS, LZSS_MODE_DECOMPRESS
from .errors import AlignmentError, ChecksumMismatch, DataSizeMismatch, ModeError
from .utils import formatData, getBufferAtIndex, isAligned

# https://opensource.apple.com/source/kext_tools/kext_tools-692.60.3/kernelcache.h.auto.html


class LZSS:
    HEADER_SIZE = 0x180
    STRUCT_SIZE = 0x18
    PADDING_SIZE = HEADER_SIZE - STRUCT_SIZE

    def __init__(self, data: bytes, mode: int) -> None:
        self.data = data
        self.data_size = len(self.data)
        self.mode = mode

        if self.mode == LZSS_MODE_DECOMPRESS:
            self.info = self.parse()
            self.kASLR = self.kASLRSupported()

        elif self.mode == LZSS_MODE_COMPRESS:
            pass

        else:
            raise ModeError(f'Unknown mode: {self.mode}')

    def parse(self) -> dict:
        head_data = getBufferAtIndex(self.data, 0, self.STRUCT_SIZE)

        (
            signature,
            compressType,
            adler32,
            uncompressedSize,
            compressedSize,
            prelinkVersion
        ) = formatData('>6I', head_data, False)

        info = {
            'signature': signature,
            'compressType': compressType,
            'adler32': adler32,
            'uncompressedSize': uncompressedSize,
            'compressedSize': compressedSize,
            'prelinkVersion': prelinkVersion
        }

        return info

    def kASLRSupported(self) -> bool:
        # prelinkVersion value >= 1 means KASLR supported
        prelinkVersion = self.info['prelinkVersion']

        if prelinkVersion >= 1:
            return True

        return False

    def checksum(self, data: bytes) -> int:
        return adler32(data)

    def makeHead(self) -> dict:
        head = {
            'signature': b'comp',
            'compressType': b'lzss',
            'adler32': 0,
            'uncompressedSize': 0,
            'compressedSize': 0,
            'prelinkVersion': self.info['prelinkVersion'] if self.mode == LZSS_MODE_DECOMPRESS else 0
        }

        return head

    def compress(self, prelinkVersion: int = 0) -> bytes:
        if self.mode != LZSS_MODE_COMPRESS:
            raise ModeError('Current mode is not set for compression!')

        header = self.makeHead()

        header['uncompressedSize'] += self.data_size
        header['adler32'] += adler32(self.data)
        header['prelinkVersion'] += prelinkVersion

        compressed_data = lzss.compress(self.data)
        header['compressedSize'] += len(compressed_data)

        convert_data = (
            header['signature'],
            header['compressType'],
            header['adler32'],
            header['uncompressedSize'],
            header['compressedSize'],
            header['prelinkVersion']
        )

        padding = b'\x00' * self.PADDING_SIZE

        data = formatData('>4s4s4I', convert_data)
        data += padding
        data += compressed_data

        return data

    def decompress(self) -> bytes:
        compressed_size = self.info['compressedSize']

        if self.data_size - compressed_size != self.HEADER_SIZE:
            raise DataSizeMismatch('Input size does not match header values!')

        data = getBufferAtIndex(self.data, self.HEADER_SIZE, compressed_size)
        data_decompressed = lzss.decompress(data)
        decompressed_size = len(data_decompressed)

        uncompressedSize = self.info['uncompressedSize']

        if decompressed_size != uncompressedSize:
            raise DataSizeMismatch('Decompressed size does not match!')

        checksum = self.info['adler32']

        if self.checksum(data_decompressed) != checksum:
            raise ChecksumMismatch('Decompressed data is corrupt!')

        return data_decompressed
