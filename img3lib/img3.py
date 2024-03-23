
from typing import Generator

from .const import (
    AES_CBC_BLOCK_SIZE,
    PADDING_EMPTY,
    PADDING_ZEROED,
    PADDING_RANDOM
)
from .errors import (
    AlignmentError,
    DataSizeMismatch,
    Img3Error,
    InfoError,
    TagError,
    VariableEmpty
)
from .utils import (
    doAES,
    formatData,
    getBufferAtIndex,
    isAligned
)


class Img3Tag:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def readTag(self, offset: int) -> Generator:
        HEAD_SIZE = 12

        i = offset

        head_data = getBufferAtIndex(self.data, i, HEAD_SIZE)
        magic, totalLength, dataLength = formatData('<3I', head_data, False)
        i += HEAD_SIZE

        tag_data = getBufferAtIndex(self.data, i, dataLength)
        i += dataLength

        pad_size = totalLength - dataLength - HEAD_SIZE
        pad_data = getBufferAtIndex(self.data, i, pad_size)
        i += pad_size

        info = {
            'magic': magic,
            'totalLength': totalLength,
            'dataLength': dataLength,
            'data': tag_data,
            'pad': pad_data
        }

        yield info


class Img3(Img3Tag):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

    def readImg3(self, offset: int) -> Generator:
        HEAD_SIZE = 20
        i = offset

        head_data = getBufferAtIndex(self.data, 0, HEAD_SIZE)
        (
            magic,
            fullSize,
            sizeNoPack,
            sigCheckArea,
            ident
        ) = formatData('<5I', head_data, False)

        i += HEAD_SIZE

        tags = []

        while i >= HEAD_SIZE and i <= sizeNoPack:
            try:
                tag = next(self.readTag(i))
            except StopIteration:
                raise TagError(f'Failed to read tag at offset: 0x{i:x}')

            tags.append(tag)

            tag_length = tag['totalLength']
            i += tag_length

        info = {
            'magic': magic,
            'fullSize': fullSize,
            'sizeNoPack': sizeNoPack,
            'sigCheckArea': sigCheckArea,
            'ident': ident,
            'tags': tags
        }

        yield info


class Img3Getter(Img3):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        try:
            self.img3 = next(self.readImg3(0))
        except StopIteration:
            raise Img3Error('Failed to read img3.')

        self.tags = self.img3['tags']

    def getTagType(self, name: str) -> Generator:
        for i, tag in enumerate(self.tags):
            magic = tag['magic'].to_bytes(4).decode('utf-8')

            if magic != name:
                continue

            yield self.tags[i]


class Img3Data(Img3Getter):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        try:
            self.DATA_SECT = next(self.getTagType('DATA'))
        except StopIteration:
            raise TagError('Failed to get DATA tag!')
        
        self.DATA = self.DATA_SECT['data']
        self.DATA_PADDING = self.DATA_SECT['pad']
        self.DATA_BLOCK_1, self.DATA_BLOCK_2 = self.getDATABlocks()

    def getTagData(self, name: str) -> tuple:
        HEAD_SIZE = 12

        # TODO Figure out whether I should account
        # for two KBAGS...

        try:
            tag = next(self.getTagType(name))
        except StopIteration:
            raise TagError('Failed to get tag!')

        expectedTotalSize = tag['totalLength']
        expectedDataSize = tag['dataLength']
        expectedPadSize = expectedTotalSize - expectedDataSize - HEAD_SIZE

        data = tag['data']

        if len(data) != expectedDataSize:
            raise DataSizeMismatch(f'Expected {expectedDataSize} but got {len(data)}!')

        pad = tag['pad']

        if len(pad) != expectedPadSize:
            raise DataSizeMismatch(f'Expected {expectedPadSize} but got {len(pad)}!')

        return data, pad

    def getDATA(self) -> tuple:
        return self.getTagData('DATA')

    def getDATABlocks(self) -> tuple:
        data, _ = self.getDATA()

        block1_size = len(data) & ~0xF
        block2_size = len(data) & 0xF

        block1_data = getBufferAtIndex(data, 0, block1_size)
        block2_data = getBufferAtIndex(data, block1_size, block2_size)

        return block1_data, block2_data


class Img3Info(Img3Data):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

    def iBootVersion(self):
        pass

    def SecurityEpoch(self):
        pass

    def SecurityDomain(self):
        pass

    def ProductionMode(self):
        pass

    def Chip(self):
        pass

    def Board(self):
        pass

    def KBAG(self):
        pass

    def SHSH(self):
        pass

    def CERT(self):
        pass

    def ECID(self):
        pass

    def TYPE(self):
        pass

    def DATA(self):
        pass

    def NONC(self):
        pass

    def CEPO(self):
        pass

    def OVRD(self):
        pass

    def RAND(self):
        pass

    def SALT(self):
        pass


class Img3Crypt(Img3Info):
    IV_LEN = 16

    AES_VALUES = (
        (128, 16),
        (192, 24),
        (256, 32)
    )

    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        try:
            self.crypt_info = next(self.getCryptInfo())
        except StopIteration:
            raise TagError('Failed to get crypt info!')

        self.padding_type = self.getPaddingType()

    def getKeyLength(self, mode: int) -> int:
        key_len = 0

        for aes, len in self.AES_VALUES:
            if aes != mode:
                continue

            key_len += len 

        if key_len < self.IV_LEN:
            raise DataSizeMismatch('Could not determine AES key length!')

        return key_len


    def getCryptInfo(self) -> Generator:
        kbags = self.getTagType('KBAG')

        for kbag in kbags:
            data_size = kbag['dataLength']
            data = kbag['data']

            head_size = 8
            head_data = getBufferAtIndex(data, 0, head_size)
            crypt_state, aes = formatData('<2I', head_data, False)

            key_len = self.getKeyLength(aes)
            key_data = getBufferAtIndex(data, head_size, data_size - head_size)

            iv, key = formatData(f'<{self.IV_LEN}s{key_len}s', key_data, False)

            info = {
                'cryptState': crypt_state,
                'aes': aes,
                'iv': iv,
                'key': key
            }

            yield info

    def getPaddingType(self) -> int:
        padding = self.DATA_PADDING
        padding_size = len(padding)
        zeroed_padding = b'\x00' * padding_size

        padding_type = 0

        if padding_size == 0:
            padding_type += PADDING_EMPTY # 0

        elif padding == zeroed_padding:
            padding_type += PADDING_ZEROED # 1

        elif padding != zeroed_padding:
            padding_type += PADDING_RANDOM # 2

        else:
            pass

        return padding_type

    def encrypt(self, iv: str, key: str) -> bytes:
        pass

    def decrypt(self, iv: str, key: str) -> bytes:
        block1_data = self.DATA_BLOCK_1
        block2_data = self.DATA_BLOCK_2
        padding_data = self.DATA_PADDING

        block1_size = len(block1_data)
        block2_size = len(block2_data)
        padding_size = len(padding_data)

        aes_type = self.crypt_info['aes']

        if not isAligned(block1_size, AES_CBC_BLOCK_SIZE):
            raise AlignmentError('Block1 must 16 byte aligned!')

        remove_padding = True if self.padding_type == PADDING_RANDOM else False
        decrypt_buffer = block1_data

        if remove_padding:
            # iOS 3.1 / 6.1.6 Kernel DATA
            decrypt_buffer += block2_data
            decrypt_buffer += padding_data

        decrypted_data = doAES(False, aes_type, decrypt_buffer, iv, key)
        data = decrypted_data

        if not remove_padding and block2_size >= 1:
            # iOS 3.0 Kernel DATA
            # Block2 is non-encrypted
            data += block2_data

        else:
            data = getBufferAtIndex(data, 0, len(data) - padding_size)

        return data
