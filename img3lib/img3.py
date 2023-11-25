
import binascii
import struct

import lzss

from .utils import aes_decrypt, getKernelChecksum

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

        # TODO Idk if this is good to do atm
        padding = [0] * paddingLength if paddingLength != 0 else None

        tag = {
            'magic': magicFormatted,
            'totalLength': totalLength,
            'dataLength': dataLength,
            'data': data,
            'pad': padding
        }

        return tag


class IMG3(Tag):
    def __init__(self, data):
        super().__init__()

        self.data = data
        self.info = self.readImg3()
        self.tags = self.info['tags']

        self.newData = None

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
            'tags': []
        }

        i = headSize

        while i != len(self.data):
            tag = self.readTag(i)

            img3_data['tags'].append(tag)

            i += tag['totalLength']

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

    def decrypt(self, iv, key):
        iv = bytes.fromhex(iv)
        key = bytes.fromhex(key)

        type_tag = self.getTagType('TYPE')
        data_tag = self.getTagType('DATA')

        # TODO
        # Check AES in KBAG

        # kbag_tag = self.getTagType('KBAG')
        # kbag_info = self.parseKBAG(kbag_tag)

        data = data_tag['data']

        dataLen = data_tag['dataLength']

        tag_type = type_tag['data'][::-1].decode()

        final_data = None

        if tag_type == 'krnl':
            lenOfDataToDecrypt = dataLen & ~0xF

            lastBlockSize = dataLen - lenOfDataToDecrypt

            dataToDecrypt = data[:lenOfDataToDecrypt]

            lastBlockData = data[-lastBlockSize:]

            decrypted_data = aes_decrypt(dataToDecrypt, iv, key)

            final_data = (decrypted_data, lastBlockData)

            # TODO
            # Allow user to disable decompression

            # This will return bytes instead
            final_data = self.decompressKernel(final_data)

        else:
            final_data = aes_decrypt(data, iv, key)

        return final_data

    def printAllImg3Info(self):
        img3_type = self.info['ident'][::-1].decode()

        print(f'Image3 type: {img3_type}')
        print(f'Full size: {self.info["fullSize"]}')
        print(f'Unpacked size: {self.info["sizeNoPack"]}')

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
        self.length = len(self.data)

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
            pass

        first = self.data[:tag_offset]

        second = packed

        third = self.data[tag_offset+len(second):]

        self.newData = first + second + third

    def replaceData(self, data):
        tmp = struct.unpack('<I', data[:4])[0]

        magic = tmp.to_bytes(4, 'little')[::-1]

        feedface = b'\xfe\xed\xfa\xce'

        if magic == feedface:
            data = self.compressKernel(data)

        newDataTag = self.makeTag('DATA', data)

        self.writeTag(newDataTag)

        return self.newData

    def makeImage(self):
        '''
        TYPE
        DATA
        VERS (iBoot)
        SEPO
        BORD (iBoot)
        KBAG (prod)
        KBAG (dev)
        SHSH
        CERT
        '''

        pass
