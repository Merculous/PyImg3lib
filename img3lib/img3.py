
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
            'magic': magic[::-1],
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
        block1_data = getBufferAtIndex(data, 0, block1_len)

        block2_len = data_len & 0xF
        block2_data = None

        # block2_len can be 0

        if block2_len != 0:
            block2_data = getBufferAtIndex(data, block1_len, block2_len)

        blocks = (
            block1_data,
            block2_data
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
            tag_magic = tag['magic'][::-1]

            if tag_magic == magic:
                tags.append(tag)

        return tags

    def getAESType(self):
        kbag_tags = self.getTagWithMagic(b'KBAG')

        for tag in kbag_tags:
            kbag_info = self.parseKBAGTag(tag)

            kbag_type = kbag_info['release']
            aes_type = kbag_info['aes_type']

            if kbag_type:
                # Is release, not development
                return aes_type

    def getTagIndex(self, magic):
        for i, tag in enumerate(self.tags):
            tag_magic = tag['magic']

            if tag_magic == magic:
                return i


class Img3Reader(Img3Getter):
    img3_head_size = 20

    def __init__(self, data):
        super().__init__()

        self.data = data

        self.head = self.readHead()
        self.tags = self.readTags()

        self.ident = self.head['ident'][::-1]

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
        tag = self.getTagWithMagic(b'DATA')[0]

        data = tag['data']
        padding = tag['pad']

        # Padding can be 0 / empty

        if not padding:
            padding = None

        block1, block2 = self.getDATABlocks(data)
        tag_data = (block1, block2, padding)

        return tag_data


class Img3Crypt(Img3Extractor):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data)

        self.iv = iv
        self.key = key

        self.aes_type = self.getAESType()

        if self.aes_type not in self.aes_supported:
            raise Exception(f'Unknown AES type: {self.aes_type}')

        self.key_len = self.aes_supported[self.aes_type]

        self.crypt_data = self.extractDATA()

        self.padding_encrypted = self.determinePaddingEncryption()

    def determinePaddingEncryption(self):
        padding = self.crypt_data[2]

        if not padding:
            # No padding
            return False

        padding_len = len(padding)

        zeroed_padding = b'\x00' * padding_len

        if padding == zeroed_padding:
            return False
        
        return True

    def decrypt(self):
        block1, block2, padding = self.crypt_data

        block1_len = len(block1)

        block2_len = 0 if not block2 else len(block2)

        padding_len = 0 if not padding else len(padding)

        total_len = block1_len + block2_len + padding_len

        remove_padding = False

        to_decrypt = None

        if self.padding_encrypted:
            to_decrypt = block1 + block2 + padding

            remove_padding = True

        else:
            # Padding is irrelevant (for now)?
            to_decrypt = block1

        decrypted = doAES(False, self.aes_type, to_decrypt, self.iv, self.key)

        if remove_padding:
            # Padding was previously encrypted.
            # Now that we decrypted, we need to remove it.

            decrypted = getBufferAtIndex(decrypted, 0, total_len - padding_len)

        else:
            # TODO Check if this code is good.
            
            # If the padding was encrypted, we need to remove it for compression.
            # If it was not, then we need to add block2 data as we only decrypted
            # block1.
            decrypted += block2

        return decrypted

    def encrypt(self, data):
        if not self.iv:
            raise Exception('Iv missing!')

        if not self.key:
            raise Exception('Key missing!')

        tag = self.makeTag(b'DATA', data)

        block1, block2 = self.getDATABlocks(tag['data'])

        padding = tag['pad']

        to_encrypt = None
        remove_padding = False

        if self.padding_encrypted:
            remove_padding = True

            pass

        else:
            # Encrypting only block1.
            # Add block2 after encryption
            to_encrypt = block1
        
        # Start encryption

        encrypted = doAES(True, self.aes_type, to_encrypt, self.iv, self.key)

        if remove_padding:
            pass

        else:
            encrypted += block2

        return encrypted


class Img3Modifier(Img3Crypt):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data, iv, key)
    
        self.new_data = None

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

    def updateImg3Data(self):
        # FIXME
        # TODO
        # Size checking

        head = [v for k, v in self.head.items()]

        head_format = formatData('<4s3I4s', head)

        new_data = head_format

        for tag in self.tags:
            tag_head = (
                tag['magic'],
                tag['totalLength'],
                tag['dataLength']
            )

            tag_head_format = formatData('<4s2I', tag_head)

            tag_head_format += tag['data']

            tag_head_format += tag['pad']

            new_data += tag_head_format

        return new_data

    def replaceTag(self, tag):
        tag_magic = tag['magic']

        tag_index = self.getTagIndex(tag_magic)

        self.tags[tag_index] = tag

        # Update img3 info with new tag

        self.updateHead()

    def replaceDATA(self, new_data):
        # This would work like replaceTag(), but
        # this function is supposed to replace data
        # that you'd want to write to a new file.

        tag = self.makeTag(b'DATA', new_data)

        self.replaceTag(tag)

        self.updateHead()

        # Update the img3 data with new DATA

        self.updateImg3Data()


class Img3File(Img3Modifier):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data, iv, key)
