
from .lzsscode import LZSS
from .utils import doAES, formatData, getBufferAtIndex, pad, padNumber

class Img3Tag:
    tag_head_size = 12

    valid_tags = (
        b'VERS', b'SEPO', b'SDOM',
        b'PROD', b'CHIP', b'BORD',
        b'KBAG', b'SHSH', b'CERT',
        b'ECID', b'TYPE', b'DATA',
        b'NONC', b'CEPO', b'OVRD',
        b'RAND', b'SALT'
    )

    def __init__(self):
        pass

    def makeTag(self, magic, data):
        if magic not in self.valid_tags:
            raise Exception(f'Invalid magic: {magic}')

        dataLength = len(data)

        padding_len = padNumber(dataLength) - dataLength

        padding = b'\x00' * padding_len

        totalLength = self.tag_head_size + dataLength + padding_len

        info = {
            'magic': magic,
            'totalLength': totalLength,
            'dataLength': dataLength,
            'data': data,
            'pad': padding
        }

        return info


class Img3Info(Img3Tag):
    aes_supported = {
        128: 16,
        192: 24,
        256: 32
    }

    def __init__(self):
        super().__init__()

    def getDATABlocks(self, data):
        data_len = len(data)

        block1_len = data_len & ~0xF
        block2_len = data_len & 0xF

        blocks = (
            getBufferAtIndex(data, 0, block1_len),
            getBufferAtIndex(data, block1_len, block2_len)
        )

        return blocks

    def parseKBAGTag(self, tag):
        tag_data = tag['data']

        head = getBufferAtIndex(tag_data, 0, 8)

        crypt_state, aes_type = formatData('<2I', head, False)

        release = True if crypt_state == 1 else False

        if aes_type not in self.aes_supported:
            raise Exception(f'Unknown AES: {aes_type}')

        iv_len = 16
        key_len = self.aes_supported[aes_type]

        key_data = getBufferAtIndex(tag_data, 8, iv_len + key_len)

        iv, key = formatData(f'>{iv_len}s{key_len}s', key_data, False)

        info = {
            'release': release,
            'aes_type': aes_type,
            'iv': iv,
            'key': key
        }

        return info


class Img3Getter(Img3Info):
    def __init__(self):
        super().__init__()

    def getTagWithMagic(self, magic):
        # We can have more than one of the same.
        # For example, 2 KBAG tags.

        tags = []

        for tag in self.tags:
            tag_magic = tag['magic']

            if tag_magic == magic:
                tags.append(tag)

        return tags

    def getAESType(self):
        kbag_tags = self.getTagWithMagic(b'KBAG'[::-1])

        for tag in kbag_tags:
            kbag_info = self.parseKBAGTag(tag)

            kbag_type = kbag_info['release']
            aes_type = kbag_info['aes_type']

            if kbag_type:
                # Is release, not development
                return aes_type

    def getTagIndex(self, magic):
        for i, tag in enumerate(self.tags):
            tag_magic = tag['magic'][::-1]

            if tag_magic == magic:
                return i


class Img3Reader(Img3Getter):
    img3_head_size = 20

    def __init__(self, data):
        super().__init__()

        self.data = data

        self.head = self.readHead()
        self.tags = self.readTags()

    def readHead(self):
        head_data = getBufferAtIndex(self.data, 0, self.img3_head_size)

        (
            magic,
            fullSize,
            sizeNoPack,
            sigCheckArea,
            ident
        ) = formatData('<4s3I4s', head_data, False)

        info = {
            'magic': magic,
            'fullSize': fullSize,
            'sizeNoPack': sizeNoPack,
            'sigCheckArea': sigCheckArea,
            'ident': ident
        }

        return info

    def readTag(self, i):
        tag_head = getBufferAtIndex(self.data, i, self.tag_head_size)

        (
            magic,
            totalLength,
            dataLength
        ) = formatData('<4s2I', tag_head, False)

        pad_len = totalLength - dataLength - self.tag_head_size

        i += self.tag_head_size

        tag_data = getBufferAtIndex(self.data, i, dataLength)

        i += dataLength

        padding = getBufferAtIndex(self.data, i, pad_len)

        i += pad_len

        info = {
            'magic': magic,
            'totalLength': totalLength,
            'dataLength': dataLength,
            'data': tag_data,
            'pad': padding
        }

        return info
    
    def readTags(self):
        fullSize = self.head['fullSize']

        tags = []

        i = self.img3_head_size

        while i != fullSize:
            tag = self.readTag(i)
            tags.append(tag)

            i += tag['totalLength']

        return tags


class Img3Extractor(Img3Reader):
    def __init__(self, data):
        super().__init__(data)

    def extractCertificate(self):
        pass

    def extractDATA(self):
        pass


class Img3Modifier(Img3Extractor):
    def __init__(self, data):
        super().__init__(data)
    
    def updateHead(self):
        sizeNoPack = 0
        sigCheckArea = 0

        tag_ignore = (b'CERT', b'SHSH')

        for tag in self.tags:
            tag_magic = tag['magic'][::-1]
            totalLength = tag['totalLength']

            sizeNoPack += totalLength

            if tag_magic not in tag_ignore:
                sigCheckArea += totalLength

        fullSize = self.img3_head_size + sizeNoPack

        self.head['fullSize'] = fullSize
        self.head['sizeNoPack'] = sizeNoPack
        self.head['sigCheckArea'] = sigCheckArea

    def replaceTag(self, tag):
        tag_magic = tag['magic']

        tag_index = self.getTagIndex(tag_magic)

        self.tags[tag_index] = tag

        # Update img3 info with new tag

        self.updateHead()

    def replaceDATA(self, new_data):
        original_tag = self.getTagWithMagic(b'DATA'[::-1])[0]

        ident = self.head['ident'][::-1]

        data = None

        # FIXME
        # padding

        if ident == b'krnl':
            lzss_obj = LZSS(new_data)
            data = lzss_obj.go()

        else:
            pass

        new_tag = self.makeTag(b'DATA', data)

        self.replaceTag(new_tag)

        pass


class Img3File(Img3Modifier):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data)

        self.iv = iv
        self.key = key

        self.aes_type = self.getAESType()

    def decrypt(self):
        data_tag = self.getTagWithMagic(b'DATA'[::-1])[0]

        data = data_tag['data']

        padding = data_tag['pad']
        padding_len = len(padding)

        # Figure out if we need to decrypt data + padding

        zeroed_padding = b'\x00' * padding_len

        padding_encrypted = True if padding != zeroed_padding else False

        # Start decryption

        data_blocks = self.getDATABlocks(data)

        iv = self.iv
        key = self.key

        final = None
        decrypted = None

        if padding_encrypted:
            pass

        else:
            decrypted = doAES(False, self.aes_type, data_blocks[0], iv, key)

            # 3.0.x seem to not include padding after decryption

            final = decrypted + data_blocks[1]

        return final

    def encrypt(self):
        pass

    def decompress(self, data):
        # Only for kernel data atm

        if self.head['ident'] != b'krnl'[::-1]:
            raise Exception('Decompression only for kernel atm!')

        lzss_obj = LZSS(data)

        decompressed_data = lzss_obj.go()

        return decompressed_data

    def compress(self):
        pass
