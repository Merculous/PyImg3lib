
import struct

import lzss

from .utils import aes_decrypt

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


class IMG3:
    def __init__(self, data, iv=None, key=None) -> None:
        self.data = data
        self.dataLen = len(self.data)

        self.iv = iv
        self.key = key

        self.tags = self.readImg3()['tags']

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
            'magic': magic,
            'fullSize': fullSize,
            'sizeNoPack': sizeNoPack,
            'sigCheckArea': sigCheckArea,
            'ident': ident,
            'tags': []
        }

        i = headSize

        while i != self.dataLen:
            tag = self.readTag(i)

            img3_data['tags'].append(tag)

            i += tag['totalLength']

        return img3_data

    def readTagInfo(self, tag):
        tagMagic_str = tag['magic'].to_bytes(4, 'little').decode()[::-1]

        print(f'Tag: {tagMagic_str}')
        print(f'Total length: {tag["totalLength"]}')
        print(f'Data length: {tag["dataLength"]}')
        print(f'Pad length: {len(tag["pad"])}')

        if tagMagic_str == 'TYPE':
            tagTypeStr = tag['data'].decode()[::-1]

            print(tagTypeStr)

        elif tagMagic_str == 'DATA':
            pass

        elif tagMagic_str == 'VERS':
            # FIXME I'm not sure if the 0F 00 00 00 is right.
            tagVers_str = tag['data'].decode()

            print(tagVers_str)

        elif tagMagic_str == 'SEPO':
            tagSepo_int = int.from_bytes(tag['data'], 'little')

            print(tagSepo_int)

        elif tagMagic_str == 'CHIP':
            tagChip_int = int.from_bytes(tag['data'], 'little')

            print(tagChip_int)

        elif tagMagic_str == 'BORD':
            tagBord_int = int.from_bytes(tag['data'], 'little')

            print(tagBord_int)

        elif tagMagic_str == 'KBAG':
            pass

        elif tagMagic_str == 'SHSH':
            pass

        elif tagMagic_str == 'CERT':
            pass

        else:
            pass

    def decrypt(self, iv, key):
        iv_len = len(iv)
        key_len = len(key)

        if iv_len != 32 or key_len != 64:
            pass

        kbag = None

        data = None

        for tag in self.tags:
            tagMagic_str = tag['magic'][::-1]

            if tagMagic_str == b'KBAG':
                kbag_type, aes_type = struct.unpack('<2I', tag['data'][:8])

                if kbag_type == 1:
                    kbag = tag['data'][8:8+48]

            elif tagMagic_str == b'DATA':
                data = tag['data']

        if not kbag or not data:
            pass

        data_decrypted = aes_decrypt(data, iv, key)

        return data_decrypted

    def decryptKernel(self):
        # signature 4
        # compression type 4
        # checksum 4
        # decompressed_len 4
        # compressed_len 4
        # padding[0x16c]

        for tag in self.tags:
            if tag['magic'][::-1] == b'DATA':
                break

        data = tag['data']

        dataLen = tag['dataLength']

        lenOfDataToDecrypt = dataLen & ~0xF

        lastBlockSize = dataLen - lenOfDataToDecrypt

        dataToDecrypt = data[:lenOfDataToDecrypt]

        lastBlockData = data[-lastBlockSize:]

        decrypted_data = aes_decrypt(dataToDecrypt, self.iv, self.key)

        return (decrypted_data, lastBlockData)

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
