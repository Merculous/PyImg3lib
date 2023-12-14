
import binascii
import struct

from .kpwn import N88_BOOTSTRAP, N88_SHELLCODE, N88_SHELLCODE_ADDRESS
from .lzsscode import LZSS
from .utils import doAES, formatData, getBufferAtIndex, pad

'''
VERS: iBoot version of the image
SEPO: Security Epoch
SDOM: Security Domain
PROD: Production Mode
CHIP: Chip to be used with. example: 0x8900 for S5L8900.
BORD: Board to be used with
KBAG: Contains the IV and key required to decrypt; encrypted with the GID Key
SHSH: RSA encrypted SHA1 hash of the file
CERT: Certificate
ECID: Exclusive Chip ID unique to every device
TYPE: Type of image, should contain the same string as the header's ident
DATA: Real content of the file
NONC: Nonce used when file was signed.
CEPO: Chip epoch
OVRD: JTAG maybe?
RAND: IDK
SALT: Encryption maybe?
'''

'''
Decryption is done using the modulus at cert + 0xA15
0xC to SHSH is SHAed
'''


class Tag:
    def __init__(self):
        pass

    def readTag(self, i, data):
        tag_head = getBufferAtIndex(data, i, 12)

        (
            magic,
            totalLength,
            dataLength
        ) = formatData('<3I', tag_head, False)

        i += 12

        tag_data = getBufferAtIndex(data, i, dataLength)

        i += dataLength

        padSize = totalLength - dataLength - 12

        padding = getBufferAtIndex(data, i, padSize)

        i += padSize

        tag = {
            'magic': magic.to_bytes(4, 'little'),
            'totalLength': totalLength,
            'dataLength': dataLength,
            'data': tag_data,
            'pad': padding
        }

        return tag

    def parseKBAG(self, tag):
        if tag is None:
            return None

        if tag['magic'] != b'KBAG'[::-1]:
            raise Exception('This is not a KBAG tag!')

        data = tag['data']

        info = {
            'dev': False,
            'aes': None,
            'iv': None,
            'key': None
        }

        aes_data = getBufferAtIndex(data, 0, 8)

        cryptState, aesType = formatData('<2I', aes_data, False)

        if cryptState == 2:
            info['dev'] = True

        info['aes'] = aesType

        crypto_data = getBufferAtIndex(data, 8, tag['dataLength'] - 8)

        iv, key = None, None

        if info['aes'] == 128:
            iv, key = formatData('<16s16s', crypto_data, False)

        elif info['aes'] == 192:
            iv, key = formatData('<16s24s', crypto_data, False)

        elif info['aes'] == 256:
            iv, key = formatData('<16s32s', crypto_data, False)

        else:
            raise Exception(f'Unknown aes: {info["aes"]}')

        info['iv'] = binascii.hexlify(iv).decode()
        info['key'] = binascii.hexlify(key).decode()

        return info

    def makeTag(self, magic, data, padding):
        valid_magic = (
            'TYPE',
            'DATA',
            'VERS',
            'SEPO',
            'BORD',
            'KBAG',
            'SHSH',
            'CERT'
        )

        if magic not in valid_magic:
            raise Exception(f'Unknown magic: {magic}')

        magicFormatted = bytes(magic, 'utf-8')[::-1]

        headsize = 12

        pad_len = len(padding)

        dataLength = len(data)

        totalLength = dataLength + headsize + pad_len

        tag = {
            'magic': magicFormatted,
            'totalLength': totalLength,
            'dataLength': dataLength,
            'data': data,
            'pad': padding
        }

        return tag


class IMG3(Tag):
    def __init__(self, data, iv=None, key=None):
        super().__init__()

        self.data = data
        self.iv = iv
        self.key = key

        self.info = self.readImg3Head()
        self.tags = self.readTags()

    def readTags(self):
        sizeNoPack = self.info['sizeNoPack']

        data = getBufferAtIndex(self.data, 20, sizeNoPack)

        i = 0

        tags = []

        while i != sizeNoPack:
            tag = self.readTag(i, data)

            tags.append(tag)

            i += tag['totalLength']

        return tags

    def readImg3Head(self):
        head = getBufferAtIndex(self.data, 0, 20)

        (
            magic,
            fullSize,
            sizeNoPack,
            sigCheckArea,
            ident
        ) = formatData('<5I', head, False)

        img3_data = {
            'magic': magic.to_bytes(4, 'little'),
            'fullSize': fullSize,
            'sizeNoPack': sizeNoPack,
            'sigCheckArea': sigCheckArea,
            'ident': ident.to_bytes(4, 'little')
        }

        return img3_data

    def getTagType(self, tag_type):
        for tag in self.tags:
            tag_magic = tag['magic'][::-1].decode()

            if tag_type == tag_magic:
                return tag

    def getAESType(self):
        kbag_tag = self.getTagType('KBAG')
        kbag_info = self.parseKBAG(kbag_tag)
        return kbag_info['aes']

    def getDATABlocks(self, data):
        data_len = len(data)

        start = data_len & ~0xF
        end = data_len & 0xF

        start_data = getBufferAtIndex(data, 0, start)
        end_data = getBufferAtIndex(data, start, end)

        blocks = (start_data, end_data)

        return blocks

    def decrypt(self, decompress=False):
        if self.iv is None:
            raise Exception('iv is not set!')

        if self.key is None:
            raise Exception('key is not set!')

        mode = 'decrypt'

        iv = self.iv
        key = self.key

        data_tag = self.getTagType('DATA')

        aes_type = self.getAESType()

        data = data_tag['data']

        padding = data_tag['pad']
        pad_len = len(padding)

        first_block, last_block = self.getDATABlocks(data)

        decrypted = None
        final = None

        # TODO
        # 3.1+ seems to have last_block encrypted
        # Also the padding can be encrypted too

        zeroed_padding = b'\x00' * pad_len

        if padding != zeroed_padding:
            # Assume that last_block and padding are encrypted?

            to_decrypt = first_block + last_block + padding

            decrypted = doAES(mode, aes_type, to_decrypt, iv, key)

            no_pad = len(decrypted) - pad_len

            # Remove padding

            final = getBufferAtIndex(decrypted, 0, no_pad)

        else:
            to_decrypt = first_block

            decrypted = doAES(mode, aes_type, to_decrypt, iv, key)

            # Seems like padding is useless here

            final = decrypted + last_block

        if decompress:
            ident = self.info['ident'][::-1]

            if ident == b'krnl':
                final = self.handleKernelData(final)

        return final

    def printAllImg3Info(self):
        img3_type = self.info['ident'][::-1].decode()

        print(f'Image3 type: {img3_type}')
        print(f'Full size: {self.info["fullSize"]}')
        print(f'Unpacked size: {self.info["sizeNoPack"]}')
        print(f'SigCheckArea: {self.info["sigCheckArea"]}')

        print('\n')

        for tag in self.tags:
            tag_magic = tag['magic'][::-1].decode()

            print(f'Magic: {tag_magic}')
            print(f'Tag length: {tag["totalLength"]}')
            print(f'Data length: {tag["dataLength"]}')

            if tag_magic == 'TYPE':
                tag_type = tag['data'][::-1].decode()

                print(f'Tag type: {tag_type}')

            if tag_magic == 'SEPO':
                epoch = struct.unpack('<I', tag['data'])[0]

                print(f'Epoch: {epoch}')

            if tag_magic == 'KBAG':
                kbag_info = self.parseKBAG(tag)

                kbag_type = None

                if kbag_info['dev'] is False:
                    kbag_type = 'prod'

                elif kbag_info['dev'] is True:
                    kbag_type = 'dev'

                print(f'KBAG type: {kbag_type}')
                print(f'AES: {kbag_info["aes"]}')
                print(f'IV: {kbag_info["iv"]}')
                print(f'Key: {kbag_info["key"]}')

            if tag_magic == 'VERS':
                vers_len = struct.unpack('<I', tag['data'][:4])[0]

                vers = struct.unpack(
                    f'<{vers_len}s', tag['data'][-vers_len:])[0]

                vers = vers.decode()

                print(f'Version length: {vers_len}')
                print(f'iBoot version: {vers}')

            if tag_magic == 'BORD':
                board = struct.unpack('<I', tag['data'])[0]

                print(f'Board: {board}')

            print('\n')

    def getTagOffset(self, magic):
        i = 20

        for tag in self.tags:
            if magic != tag['magic']:
                i += tag['totalLength']
            else:
                return i

    def getLengthOfDataAfterTag(self, magic):
        sizeNoPack = self.info['sizeNoPack']

        end = 0

        for tag in self.tags:
            tag_magic = tag['magic'][::-1].decode()

            tag_size = tag['totalLength']

            end += tag_size

            if tag_magic == magic:
                break

        length_after_tag = sizeNoPack - end

        return length_after_tag

    def writeTag(self, tag):
        magic = tag['magic']
        magic_str = magic[::-1].decode()

        tag_head = (
            magic,
            tag['totalLength'],
            tag['dataLength']
        )

        tag_data = tag['data']
        data_len = len(tag_data)

        tag_padding = tag['pad']
        # pad_len = len(tag_padding)

        if data_len != tag['dataLength']:
            raise Exception('Tag data does not match dataLength!')

        head = formatData('<4s2I', tag_head)

        final = head + tag_data + tag_padding
        final_len = len(final)

        if tag['totalLength'] != final_len:
            raise Exception('Total length does not match other lengths!')

        # Get offsets of the original img3 to insert new data

        tag_offset = self.getTagOffset(magic)

        data_head = getBufferAtIndex(self.data, 0, tag_offset)

        # Get the original tag data

        original_tag = self.getTagType(magic_str)

        data_end = tag_offset + original_tag['totalLength']

        end_len = self.getLengthOfDataAfterTag(magic_str)

        rest_data = getBufferAtIndex(self.data, data_end, end_len)

        # Put the new data together

        self.data = data_head + final + rest_data

        # Update self.info and self.tags

        self.info = self.readImg3Head()
        self.tags = self.readTags()

        self.updateHead()

    def replaceData(self, data):
        ident = self.info['ident'][::-1]

        new_data = None

        if ident == b'krnl':
            new_data = self.handleKernelData(data)

        else:
            new_data = data

        new_data_len = len(new_data)

        aes_type = self.getAESType()

        iv = self.iv
        key = self.key

        # TODO
        # Figure out how xpwntool is managing to have a 25 byte padding...

        padded = pad(new_data)
        padded_len = len(padded)

        pad_count = padded_len - new_data_len

        encrypted = doAES('encrypt', aes_type, padded, iv, key)

        # Remove padding

        no_padding = getBufferAtIndex(encrypted, 0, padded_len - pad_count)

        padding = getBufferAtIndex(encrypted, new_data_len, pad_count)

        data_tag = self.makeTag('DATA', no_padding, padding)

        self.writeTag(data_tag)

    def extractCertificate(self):
        cert_tag = self.getTagType('CERT')

        cert_data = cert_tag['data']

        return cert_data

    def updateHead(self):
        fullSize = 20
        sizeNoPack = 0
        sigCheckArea = 0

        ignore = (
            b'SHSH'[::-1],
            b'CERT'[::-1]
        )

        for tag in self.tags:
            fullSize += tag['totalLength']
            sizeNoPack += tag['totalLength']

            if tag['magic'] not in ignore:
                sigCheckArea += tag['totalLength']

        self.info['fullSize'] = fullSize
        self.info['sizeNoPack'] = sizeNoPack
        self.info['sigCheckArea'] = sigCheckArea

        head = (
            self.info['magic'],
            self.info['fullSize'],
            self.info['sizeNoPack'],
            self.info['sigCheckArea'],
            self.info['ident']
        )

        new_head = struct.pack('<4s3I4s', *head)

        body = self.data[20:]

        self.data = new_head + body

    def do3GSLLBHax(self):
        type_tag = self.getTagType('TYPE')

        image_type = type_tag['data'][::-1].decode()

        if image_type != 'illb':
            raise Exception(f'Got image type: {image_type}. Expected illb!')

        # Update DATA's first dword with shellcode address

        data_tag = self.getTagType('DATA')
        data_tag_data = data_tag['data']
        padding = data_tag['pad']

        dword = getBufferAtIndex(data_tag_data, 0, 4)

        data = getBufferAtIndex(data_tag_data, 4, data_tag['dataLength'] - 4)

        patched_data = N88_SHELLCODE_ADDRESS + data

        new_data_tag = self.makeTag('DATA', patched_data, padding)

        self.writeTag(new_data_tag)

        cert_tag = self.getTagType('CERT')
        cert_data = cert_tag['data']
        cert_pad = cert_tag['pad']

        cert_start = self.getTagOffset(b'CERT'[::-1])

        cert_end = cert_start + cert_tag['totalLength']

        shellcode = b''.join(N88_SHELLCODE)
        shellcode_len = len(shellcode)

        bootstrap = b''.join(N88_BOOTSTRAP)

        padding_len = 0xfb0

        bootstrap_start = 0x24000

        shellcode_start = bootstrap_start - padding_len - shellcode_len

        zeroes_after_cert = shellcode_start - cert_end

        n8824k_data = (
            cert_data + cert_pad,
            b'\x00' * zeroes_after_cert,
            shellcode.replace(b'\xAA\xBB\xCC\xDD', dword),
            b'\x00' * padding_len,
            bootstrap
        )

        patched_cert_data = b''.join(n8824k_data)

        # This data should already be padded?

        patched_cert_tag = self.makeTag('CERT', patched_cert_data, b'')

        # Check that CERT is the last tag

        last_tag = self.tags[-1]
        last_tag_magic = last_tag['magic'][::-1].decode()

        if last_tag_magic != 'CERT':
            raise Exception('Expected last tag to be CERT, but it is not!')

        # Inject new CERT data so we can satisfy my writeTag()

        self.tags[-1] = patched_cert_tag

        self.updateHead()

        self.writeTag(patched_cert_tag)

        # xpwntool turns all padding values to '\x00' in TYPE

        type_padding = type_tag['pad']
        type_padding_len = len(type_padding)

        type_padding = b'\x00' * type_padding_len

        type_tag['pad'] = type_padding

        self.writeTag(type_tag)

    def handleKernelData(self, data):
        # Check that our img3 is actually a kernel

        if self.info['ident'] != b'krnl'[::-1]:
            raise Exception('This is not a kernel!')

        # Only work on decrypted data

        lzss_obj = LZSS(data)
        lzss_data = lzss_obj.go()

        return lzss_data
