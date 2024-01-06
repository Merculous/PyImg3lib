
from binascii import hexlify

from .kpwn import N88_BOOTSTRAP, N88_SHELLCODE, N88_SHELLCODE_ADDRESS
from .lzsscode import LZSS
from .utils import doAES, formatData, getBufferAtIndex, pad


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

        padding = 0

        # If magic is DATA, pad to 64 byte multiple

        if magic == b'DATA':
            padded = pad(64, data)

            padding = len(padded) - dataLength

            data = padded

        totalLength = self.tag_head_size + dataLength + padding

        info = {
            'magic': magic[::-1],
            'totalLength': totalLength,
            'dataLength': dataLength,
            'data': data,
            'pad': b'\x00' * padding
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
        block2_data = b''

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
    img3_head_size = 20

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

    def getPositionOfTag(self, magic):
        pos = self.img3_head_size

        for tag in self.tags:
            size = tag['totalLength']

            if tag['magic'][::-1] != magic:
                pos += size
            else:
                break

        return pos


class Img3Reader(Img3Getter):
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
        cert_tag = self.getTagWithMagic(b'CERT')[0]

        data = cert_tag['data']

        return data

    def extractDATA(self):
        tag = self.getTagWithMagic(b'DATA')[0]

        data = tag['data']
        padding = tag['pad']

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

        self.encrypted_truncate = 0

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

            # If the padding was encrypted, we need to remove it
            # for compression. If it was not, then we need to add
            # block2 data as we only decrypted block1.

            if block2:
                decrypted += block2

        return decrypted

    def encrypt(self, data):
        if not self.iv:
            raise Exception('Iv missing!')

        if not self.key:
            raise Exception('Key missing!')

        block1, block2 = self.getDATABlocks(data)

        tag = self.makeTag(b'DATA', data)

        padding = tag['pad']

        to_encrypt = None
        remove_padding = False

        if self.padding_encrypted:
            remove_padding = True

            to_encrypt = block1 + block2 + padding

        else:
            # Encrypting only block1.
            # Add block2 after encryption
            to_encrypt = block1

        # Start encryption

        encrypted = doAES(True, self.aes_type, to_encrypt, self.iv, self.key)

        if remove_padding:
            self.encrypted_truncate = len(padding)

        else:
            if block2:
                encrypted += block2

        return encrypted


class Img3LZSS(Img3Crypt):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data, iv, key)

        self.lzss_obj = None

    def getLZSSVersion(self, data):
        i = self.lzss_obj.lzss_head - 4

        version_raw = getBufferAtIndex(data, i, 4)

        version_format = formatData('>I', version_raw, False)[0]

        return version_format

    def handleKernelData(self, data):
        # Decrypt to get the kernel version

        decrypted = self.decrypt()

        # Setup LZSS object

        self.lzss_obj = LZSS(decrypted)

        version = self.getLZSSVersion(decrypted)

        self.lzss_obj.version = version

        # Change lzss.data with our actual data

        self.lzss_obj.data = data

        output = self.lzss_obj.go()

        return output


class Img3Modifier(Img3LZSS):
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

        if self.encrypted_truncate != 0:
            # TODO CLEAN THIS
            # Seems like this is needed but could be made better

            tag_data = tag['data']

            tag['dataLength'] -= self.encrypted_truncate
            tag['data'] = getBufferAtIndex(tag_data, 0, tag['dataLength'])
            tag['pad'] = getBufferAtIndex(
                tag_data, tag['dataLength'], self.encrypted_truncate)

        self.replaceTag(tag)

        self.updateHead()

        # Update the img3 data with new DATA

        self.updateImg3Data()


class Img3File(Img3Modifier):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data, iv, key)

    def do24KPWN(self):
        type_tag = self.getTagWithMagic(b'TYPE')[0]
        data_tag = self.getTagWithMagic(b'DATA')[0]
        cert_tag = self.getTagWithMagic(b'CERT')[0]

        # Update first 4 bytes of DATA with shellcode address

        data_tag_data = data_tag['data']
        data_tag_data_len = data_tag['dataLength']

        data_tag_dword = getBufferAtIndex(data_tag_data, 0, 4)
        data_tag_rest = getBufferAtIndex(
            data_tag_data, 4, data_tag_data_len - 4)

        new_data = N88_SHELLCODE_ADDRESS + data_tag_rest

        # Replace data tag with the modified

        new_data_tag = self.makeTag(b'DATA', new_data)

        self.replaceTag(new_data_tag)

        if len(new_data) != data_tag_data_len:
            raise Exception('New data length mismatch!')

        # Begin CERT modification

        cert_len = cert_tag['totalLength']
        cert_data = cert_tag['data']
        cert_pad = cert_tag['pad']

        cert_start = self.getPositionOfTag(b'CERT')
        cert_end = cert_start + cert_len

        shellcode = b''.join(N88_SHELLCODE)
        bootstrap = b''.join(N88_BOOTSTRAP)

        padding = b'\x00' * 0xfb0
        bootstrap_start = 0x24000

        shellcode_start = bootstrap_start - len(padding) - len(shellcode)

        zeroes_after_cert = b'\x00' * (shellcode_start - cert_end)

        # Put our 24kpwn data together

        n8824k_data = (
            cert_data + cert_pad,
            zeroes_after_cert,
            shellcode.replace(b'\xAA\xBB\xCC\xDD', data_tag_dword),
            padding,
            bootstrap
        )

        n8824k_data = b''.join(n8824k_data)

        # Replace CERT

        n8824k_cert_tag = self.makeTag(b'CERT', n8824k_data)

        # FIXME
        # Remove padding

        n8824k_cert_tag_pad_len = len(n8824k_cert_tag['pad'])

        n8824k_cert_tag['totalLength'] -= n8824k_cert_tag_pad_len

        n8824k_cert_tag['pad'] = b''

        self.replaceTag(n8824k_cert_tag)

        # Replace TYPE padding with zeroes cause this is what xpwntool does.
        # Also just to produce exact LLB's.

        type_tag_pad_len = len(type_tag['pad'])

        type_tag_zeroed_padding = b'\x00' * type_tag_pad_len

        type_tag['pad'] = type_tag_zeroed_padding

        self.replaceTag(type_tag)

        pwned_data = self.updateImg3Data()
        pwned_data_len = len(pwned_data)

        # Check that n8824k_data is the correct size

        n8824k_expected_size = 0x241d0

        if pwned_data_len != n8824k_expected_size:
            raise Exception(
                f'n8824k data size mismatch! Size: {hex(pwned_data_len)}!')

        return pwned_data

    def printImg3Info(self):
        head = self.head

        for k, v in head.items():
            if isinstance(v, bytes):
                # Reverse img3 magic and ident
                v = v[::-1].decode('utf-8')

            print(f'{k}: {v}')

        tags = self.tags

        current_tag = None

        ignore = ('TYPE', 'DATA')

        for tag in tags:
            for k, v in tag.items():
                if k == 'magic':
                    v = v[::-1].decode('utf-8')

                    current_tag = v

                    print(f'Tag: {current_tag}')

                elif k == 'data':
                    if current_tag in ignore:
                        continue

                    if current_tag == 'VERS':
                        str_len = formatData('<I', v[:4], False)[0]
                        _str = getBufferAtIndex(v, 4, str_len).decode('utf-8')

                        print(f'Str length: {str_len}')
                        print(_str)

                    elif current_tag == 'SEPO':
                        sepo = formatData('<I', v, False)[0]

                        print(f'SEPO: {sepo}')

                    elif current_tag == 'CHIP':
                        chip = formatData('<I', v, False)[0]

                        print(f'Chip: {chip}')

                    elif current_tag == 'BORD':
                        bord = formatData('<I', v, False)[0]

                        print(f'Bord: {bord}')

                    elif current_tag == 'KBAG':
                        kbag_info = self.parseKBAGTag(tag)

                        print(f'Release: {kbag_info["release"]}')
                        print(f'AES: {kbag_info["aes_type"]}')

                        iv = hexlify(kbag_info['iv']).decode('utf-8')
                        key = hexlify(kbag_info['key']).decode('utf-8')

                        print(f'Iv: {iv}')
                        print(f'Key: {key}')

                elif k == 'pad':
                    pad_len = len(v)

                    print(f'Padding: {pad_len}')

                else:
                    print(f'{k}: {v}')

    def findDifferences(self, data):
        head1 = self.head
        head2 = data.head

        tags1 = self.tags
        tags2 = data.tags

        for (k, v), (kk, vv) in zip(head1.items(), head2.items()):
            if v != vv:
                print(f'{k}: {v} -> {vv}')

        tag_magic = None

        for tag1, tag2 in zip(tags1, tags2):
            for (k, v), (kk, vv) in zip(tag1.items(), tag2.items()):
                if v != vv:
                    tag_magic = tag1['magic'][::-1]

                    if k == 'data':
                        continue

                    if k == 'pad':
                        pad1_len = len(v)
                        pad2_len = len(vv)

                        print(f'{k}: {pad1_len} -> {pad2_len}')

                        continue

                    print(f'Found a difference in {tag_magic}')
                    print(f'{k}: {v} -> {vv}')

            tag_magic = None
