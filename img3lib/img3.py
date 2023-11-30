
import binascii
import struct

import lzss

from .kpwn import N88_BOOTSTRAP, N88_DATA, N88_SHELLCODE
from .utils import aes, getKernelChecksum, getSHA1

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
OVRD:
RAND:
SALT:
'''

'''
Decryption is done using the modulus at cert + 0xA15
0xC to SHSH is SHAed
'''


class Tag:
    def __init__(self):
        pass

    def readTag(self, i):
        '''
        typedef struct img3Tag {
            uint32_t magic;            // see below
            uint32_t totalLength;      // length of tag including "magic" and these two length values
            uint32_t dataLength;       // length of tag data
            uint8_t  data[dataLength];
            uint8_t  pad[totalLength - dataLength - 12]; // Typically padded to 4 byte multiple
        };
        '''

        magic, totalLength, dataLength = struct.unpack(
            '<3I', self.data[i:i+12])

        i += 12

        tag_data = self.data[i:i+dataLength]

        i += dataLength

        padSize = totalLength - dataLength - 12

        padding = self.data[i:i+padSize]

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

        data = tag['data']

        info = {
            'dev': False,
            'aes': None,
            'iv': None,
            'key': None
        }

        i = 0

        cryptState, aesType = struct.unpack('<2I', data[i:8])

        if cryptState == 2:
            info['dev'] = True

        info['aes'] = aesType

        i += 8

        if info['aes'] == 256:
            iv, key = struct.unpack('<16s32s', data[i:len(data)])
        else:
            pass

        info['iv'] = binascii.hexlify(iv).decode()
        info['key'] = binascii.hexlify(key).decode()

        return info

    def makeTag(self, magic, data):
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

        dataLength = len(data)

        totalLength = dataLength + headsize

        paddingLength = totalLength - dataLength - headsize

        padding = b'\x00' * paddingLength if paddingLength != 0 else None

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

        self.info = self.readImg3()
        self.tags = self.info['tags']

    def readTags(self, i, data):
        tags = []

        while i != len(data):
            tag = self.readTag(i)

            tags.append(tag)

            i += tag['totalLength']

        return tags

    def readImg3(self):
        '''
        typedef struct img3File {
            uint32_t magic;       // ASCII_LE("Img3")
            uint32_t fullSize;    // full size of fw image
            uint32_t sizeNoPack;  // size of fw image without header
            uint32_t sigCheckArea;// although that is just my name for it, this is the
                                // size of the start of the data section (the code) up to
                                // the start of the RSA signature (SHSH section)
            uint32_t ident;       // identifier of image, used when bootrom is parsing images
                                // list to find LLB (illb), LLB parsing it to find iBoot (ibot),
                                // etc.
            img3Tag  tags[];      // continues until end of file
        };
        '''

        headSize = 20

        magic, fullSize, sizeNoPack, sigCheckArea, ident = struct.unpack(
            '<5I', self.data[:headSize])

        img3_data = {
            'magic': magic.to_bytes(4, 'little'),
            'fullSize': fullSize,
            'sizeNoPack': sizeNoPack,
            'sigCheckArea': sigCheckArea,
            'ident': ident.to_bytes(4, 'little'),
            'tags': self.readTags(headSize, self.data)
        }

        return img3_data

    def getTagType(self, tag_type):
        for tag in self.tags:
            tag_magic = tag['magic'][::-1].decode()

            if tag_type == tag_magic:
                return tag

    def decompressKernel(self, data):
        headsize = 20

        (
            signature,
            compression_type,
            checksum,
            decompressed_len,
            compressed_len
        ) = struct.unpack('<5I', data[0][:headsize])

        signature = signature.to_bytes(4, 'little')
        compression_type = compression_type.to_bytes(4, 'little')

        if signature != b'comp' or compression_type != b'lzss':
            raise Exception('Kernel DATA header is bad!')

        dataAfterPadding = data[0][0x180:]

        dataToDecompress = dataAfterPadding + data[1]

        decompressedData = lzss.decompress(dataToDecompress)

        return decompressedData

    def decrypt(self, aes_type=None):
        if self.iv is None:
            raise Exception('iv is not set!')

        if self.key is None:
            raise Exception('key is not set!')

        type_tag = self.getTagType('TYPE')
        data_tag = self.getTagType('DATA')

        kbag_tag = self.getTagType('KBAG')
        kbag_info = self.parseKBAG(kbag_tag)

        if kbag_info:
            aes_type = kbag_info['aes']

        if aes_type is None:
            raise Exception('Please select the AES type!')

        data = data_tag['data']

        dataLen = data_tag['dataLength']

        tag_type = type_tag['data'][::-1].decode()

        final_data = None

        edge_cases = ('krnl', 'logo', 'recm')

        if tag_type in edge_cases:
            lenOfDataToDecrypt = dataLen & ~0xF

            lastBlockSize = dataLen - lenOfDataToDecrypt

            dataToDecrypt = data[:lenOfDataToDecrypt]

            lastBlockData = data[-lastBlockSize:]

            decrypted_data = aes(
                'decrypt', aes_type, dataToDecrypt, self.iv, self.key)

            final_data = (decrypted_data, lastBlockData)

            # TODO
            # Allow user to disable decompression

            if tag_type == 'krnl':
                # This will return bytes instead
                final_data = self.decompressKernel(final_data)

            else:
                final_data = decrypted_data + lastBlockData

        else:
            final_data = aes(
                'decrypt', aes_type, data, self.iv, self.key)

        return final_data

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

                else:
                    pass

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

    def compressKernel(self, data):
        compressed = lzss.compress(data)

        padding_len = 0x180 - 0x14

        padding = [0] * padding_len

        output = (
            b'comp',
            b'lzss',
            getKernelChecksum(compressed),
            len(data),
            len(compressed)
        )

        output_packed = struct.pack('<4s4s3I', *output)
        padding_packed = struct.pack(f'{padding_len}B', *padding)

        final = output_packed + padding_packed + compressed

        return final

    def getTagOffset(self, magic):
        i = 20

        for tag in self.tags:
            if magic != tag['magic']:
                i += tag['totalLength']
            else:
                return i

    def writeTag(self, tag):
        tag_offset = self.getTagOffset(tag['magic'])

        tag_head = (
            tag['magic'],
            tag['totalLength'],
            tag['dataLength']
        )

        packed = None

        if tag['pad'] is None:
            packed = struct.pack(
                f'<4s2I{tag["dataLength"]}B', *tag_head, *tag['data'])
        else:
            padding_len = len(tag['pad'])

            packed = struct.pack(
                f'<4s2I{tag["dataLength"]}B{padding_len}B', *tag_head, *tag['data'], *tag['pad'])

        first = self.data[:tag_offset]

        second = packed

        third = self.data[tag_offset+len(second):]

        self.data = first + second + third

        # Update self.info and self.tags

        self.info = self.readImg3()
        self.tags = self.info['tags']

    def replaceData(self, data, aes_type=None):
        magic = struct.unpack('<I', data[:4])[0]

        magic = magic.to_bytes(4, 'little')[::-1]

        # kernel
        feedface = b'\xfe\xed\xfa\xce'

        # Applelogo / RecoveryMode (iBootIm)
        iboot = b'iBoo'[::-1]

        kbag_tag = self.getTagType('KBAG')
        kbag_info = self.parseKBAG(kbag_tag)

        if kbag_info:
            aes_type = kbag_info['aes']

        if aes_type is None:
            raise Exception('Please select the AES type!')

        if magic == feedface or magic == iboot:
            if magic == feedface:
                data = self.compressKernel(data)

            # 3.0 / 3.0.1 have the last block
            # of DATA unencrypted

            if self.iv and self.key:
                data_len = len(data)

                toEncrypt = len(data) & ~0xF

                lastBlock = data_len - toEncrypt

                first = data[:toEncrypt]

                second = data[-lastBlock:]

                third = aes(
                    'encrypt', aes_type, first, self.iv, self.key)

                data = third + second

        else:
            if self.iv and self.key:
                data = aes('encrypt', aes_type, data, self.iv, self.key)

        newDataTag = self.makeTag('DATA', data)

        self.writeTag(newDataTag)

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

        cert_tag = self.getTagType('CERT')
        cert_data = cert_tag['data']
        cert_pad_len = len(cert_tag['pad'])

        zero_padding = b'\x00' * cert_pad_len

        zero_1st_section = b'\x00' * 0x126b0

        zero_2nd_section = b'\x00' * 0xfc0

        shellcode = b''.join(N88_SHELLCODE)

        bootstrap = b''.join(N88_BOOTSTRAP)

        new_data = cert_data + zero_padding + zero_1st_section + \
            shellcode + zero_2nd_section + bootstrap

        new_data_len = len(new_data)

        if new_data_len != 81964:
            raise Exception('LLB 24kpwn creation failed!')

        new_cert_tag = self.makeTag('CERT', new_data)

        good_cert_SHA1 = 'd332265111a9c0c4ae9b1ca30a589cc5ad56a074'

        new_data_SHA1 = getSHA1(new_data)

        if new_data_SHA1 != good_cert_SHA1:
            raise Exception(
                f'Data size is correct, but hash is not: {new_data_SHA1}')

        good_data_SHA1 = '20811e9c4b20a487dd7a522fb926eecf015be022'

        data_tag = self.getTagType('DATA')
        data_tag_len = data_tag['dataLength']

        data_tag_data = self.decrypt()

        new_data_head = b''.join(N88_DATA)

        second = data_tag_data[20:data_tag_len]

        third = new_data_head + second

        new_data_tag_data_SHA1 = getSHA1(third)

        if new_data_tag_data_SHA1 != good_data_SHA1:
            raise Exception(
                'First 20 bytes of DATA failed to patch correctly!')

        self.replaceData(third)

        self.writeTag(new_cert_tag)

        # xpwntool just overwrites padding with 0's
        # While I don't think this really matters,
        # I'll do it anyway so that the code will
        # produced an EXACT match, cause why not.

        type_tag = self.getTagType('TYPE')

        type_padding = type_tag['pad']
        padding_len = len(type_padding)

        type_tag['pad'] = b'\x00' * padding_len

        self.writeTag(type_tag)

        self.updateHead()
