
import lzss

from .utils import formatData, getBufferAtIndex, getKernelChecksum


class LZSS:
    lzss_head = 0x18
    lzss_end = 0x180
    lzss_padding = lzss_end - lzss_head

    def __init__(self, data) -> None:
        self.data = data

        self.mode = None
        self.version = None

    def determineMode(self):
        buffer = getBufferAtIndex(self.data, 0, 8)

        mode = None

        if buffer == b'complzss':
            mode = 'decompress'

        else:
            head = getBufferAtIndex(buffer, 0, 4)

            head = formatData('<I', head, False)[0].to_bytes(4)

            kernel_magic = b'\xfe\xed\xfa\xce'

            if head == kernel_magic:
                mode = 'compress'

        return mode

    def compress(self):
        compressed = lzss.compress(self.data)
        compressed_len = len(compressed)

        to_pack = (
            b'comp',
            b'lzss',
            getKernelChecksum(self.data),
            len(self.data),
            compressed_len,
            self.version
        )

        head = formatData('>4s4s4I', to_pack)

        if len(head) != self.lzss_head:
            raise Exception('Packed length is not 0x18!')

        head_with_padding = head + (b'\x00' * self.lzss_padding)

        if len(head_with_padding) != self.lzss_end:
            raise Exception('Head + padding length is not 0x180!')

        final = head_with_padding + compressed

        return final

    def decompress(self):
        head = getBufferAtIndex(self.data, 0, self.lzss_head)

        (
            signature,
            compression_type,
            checksum,
            decompressed_len,
            compressed_len,
            version
        ) = formatData('>4s4s4I', head, False)

        self.version = version

        if signature != b'comp':
            raise Exception('Signature is not comp!')

        if compression_type != b'lzss':
            raise Exception('Compression is not lzss!')

        expected_len = len(self.data) - self.lzss_end

        if expected_len != compressed_len:
            raise Exception('Compressed length does not match!')

        data = getBufferAtIndex(self.data, self.lzss_end, expected_len)

        # Check decompressed data length

        decompressed_data = lzss.decompress(data)
        decompressed_data_len = len(decompressed_data)

        if decompressed_data_len != decompressed_len:
            raise Exception('Decompressed length does not match!')

        # Do adler32 (cheksum) on decompressed data

        decompressed_checksum = getKernelChecksum(decompressed_data)

        if decompressed_checksum != checksum:
            raise Exception('Adler32 does not match!')

        return decompressed_data

    def go(self):
        data = None

        self.mode = self.determineMode()

        if self.mode == 'compress':
            data = self.compress()

        elif self.mode == 'decompress':
            data = self.decompress()

        else:
            raise Exception(f'Unknown mode: {self.mode}')

        return data
