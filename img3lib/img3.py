
from binascii import hexlify

from binpatch.utils import getBufferAtIndex

from .der import extractNestedImages, extractPublicKeyFromDER
from .kpwn import (KPWN_BOOTSTRAP_OFFSET, KPWN_SHELLCODE_OFFSET,
                   N72_24KPWN_SIZE, N72_BOOTSTRAP, N72_SHELLCODE,
                   N72_SHELLCODE_ADDRESS, N88_24KPWN_SIZE, N88_BOOTSTRAP,
                   N88_SHELLCODE, N88_SHELLCODE_ADDRESS)
from .lzsscode import LZSS
from .utils import (doAES, doRSACheck, formatData, getSimilarityBetweenData,
                    isAligned, pad)


class BadMagic(Exception):
    pass


class BadAESType(Exception):
    pass


class TagNotFound(Exception):
    pass


class AlignmentError(Exception):
    pass


class MissingArgument(Exception):
    pass


class IdentityError(Exception):
    pass


class SizeError(Exception):
    pass


class MissingBlobType(Exception):
    pass


class BadSEPOValue(Exception):
    pass


class BadBORDValue(Exception):
    pass


class BadCHIPValue(Exception):
    pass


class BadDATA(Exception):
    pass


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

    valid_types = (
        b'krnl', b'rdsk', b'bat1',
        b'chg1', b'illb', b'batF',
        b'nsrv', b'chg0', b'dtre',
        b'glyC', b'bat0', b'logo',
        b'ibot', b'glyP', b'recm',
        b'ibec', b'ibss', b'cert' # 'cert' != 'CERT'
    )

    valid_sepos = (
        1, 2, 3,
        4, 5, 16,
        17
    )

    valid_boards = (
        0, 2, 4,
        6, 8, 10,
        14
    )

    valid_chips = (
        0x8930, 0x8940, 0x8942,
        0x8950
    )

    def makeTag(self, magic, data):
        if magic not in self.valid_tags:
            raise BadMagic(f'Invalid magic: {magic}')

        dataLength = len(data)
        totalLength = dataLength + self.tag_head_size

        paddedData = pad(4, data)
        paddedSize = len(paddedData)

        paddingSize = paddedSize - dataLength
        totalLength += paddingSize

        data = paddedData

        info = {
            'magic': magic[::-1],
            'totalLength': totalLength,
            'dataLength': dataLength,
            'data': getBufferAtIndex(data, 0, dataLength),
            'pad': getBufferAtIndex(data, dataLength, paddingSize) if paddingSize != 0 else b''
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
            raise BadAESType(f'Unknown AES: {aes_type}')

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

        if not tags:
            raise TagNotFound(f'Tag with magic {magic} not found!')

        return tags


    def getAESType(self):
        try:
            kbag_tags = self.getTagWithMagic(b'KBAG')
        except TagNotFound:
            return

        for tag in kbag_tags:
            kbag_info = self.parseKBAGTag(tag)

            kbag_type = kbag_info['release']
            aes_type = kbag_info['aes_type']

            if not kbag_type:
                continue

            # Is release, not development
            return aes_type

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

    def readHead(self, i=0, data=None):
        if data is None:
            data = self.data

        head_data = getBufferAtIndex(data, i, self.img3_head_size)

        (
            magic,
            fullSize,
            sizeNoPack,
            sigCheckArea,
            ident
        ) = formatData('<4s3I4s', head_data, False)

        if magic != b'Img3'[::-1]:
            raise BadMagic('This is not an img3!')

        info = {
            'magic': magic,
            'fullSize': fullSize,
            'sizeNoPack': sizeNoPack,
            'sigCheckArea': sigCheckArea,
            'ident': ident
        }

        return info

    def readTag(self, i=0, data=None):
        if data is None:
            data = self.data

        tag_head = getBufferAtIndex(data, i, self.tag_head_size)

        (
            magic,
            totalLength,
            dataLength
        ) = formatData('<4s2I', tag_head, False)

        if magic[::-1] not in self.valid_tags:
            raise BadMagic(f'Unknown magic at index: {i}')

        pad_len = totalLength - dataLength - self.tag_head_size

        i += self.tag_head_size

        tag_data = getBufferAtIndex(data, i, dataLength)

        i += dataLength

        padding = b''

        if pad_len >= 1:
            padding += getBufferAtIndex(data, i, pad_len)

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
            try:
                tag = self.readTag(i)
            except BadMagic as e:
                print(f'Got error: {e}')
                print(f'Fullsize: {self.head["fullSize"]}')
                print(f'SizeNoPack: {self.head["sizeNoPack"]}')
                print('Possible img3 sizing is incorrect!')
                exit(1)
            else:
                tags.append(tag)
                i += tag['totalLength']

        return tags


class Img3Extractor(Img3Reader):
    def __init__(self, data):
        super().__init__(data)

    def extractCertificate(self):
        try:
            cert_tag = self.getTagWithMagic(b'CERT')[0]
        except TagNotFound:
            return

        data = cert_tag['data']
        return data

    def extractDATA(self):
        try:
            tag = self.getTagWithMagic(b'DATA')[0]
        except TagNotFound:
            return

        data = tag['data'] + tag['pad']
        return data

    def extractSHSH(self):
        try:
            tag = self.getTagWithMagic(b'SHSH')[0]
        except TagNotFound:
            return

        data = tag['data']
        return data


class Img3Crypt(Img3Extractor):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data)

        self.iv = iv
        self.key = key
        self.aes_type = self.getAESType()
        self.key_len = self.aes_supported.get(self.aes_type, None)
        self.crypt_data = self.setupCryptData()
        self.padding_encrypted = self.determinePaddingEncryption()
        self.encrypted_truncate = 0
        self.nested_images = self.getNestedImages()

        try:
            self.getTagWithMagic(b'KBAG')
        except TagNotFound:
            self.image_encrypted = False
        else:
            self.image_encrypted = True

    def setupCryptData(self):
        try:
            dataTag = self.getTagWithMagic(b'DATA')[0]
        except TagNotFound:
            return

        data = dataTag['data']
        padding = dataTag['pad']
        block1, block2 = self.getDATABlocks(data)
        return block1, block2, padding

    def determinePaddingEncryption(self):
        if self.crypt_data is None:
            return

        paddingData = self.crypt_data[2]

        # Padding is 0 aka b''
        if not paddingData:
            return

        paddingSize = len(paddingData)
        paddingZeroed = b'\x00' * paddingSize

        if paddingData == paddingZeroed:
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

        if not isAligned(len(to_decrypt), 16):
            raise AlignmentError('Data to decrypt is not 16 aligned!')

        if self.image_encrypted:
            if not self.iv:
                raise MissingArgument('Iv missing!')

            if not self.key:
                raise MissingArgument('Key missing!')

            decrypted = doAES(False, self.aes_type, to_decrypt, self.iv, self.key)
        else:
            decrypted = to_decrypt

        if remove_padding:
            # Padding was previously encrypted.
            # Now that we decrypted, we need to remove it.

            decrypted = getBufferAtIndex(decrypted, 0, total_len - padding_len)

        if not remove_padding and block2:
            # TODO Check if this code is good.

            # If the padding was encrypted, we need to remove it
            # for compression. If it was not, then we need to add
            # block2 data as we only decrypted block1.

            decrypted += block2

        return decrypted

    def encrypt(self, data):
        block1, block2 = self.getDATABlocks(data)

        tag = self.makeTag(b'DATA', data)

        padding = tag['pad']

        to_encrypt = block1
        remove_padding = False

        if self.padding_encrypted:
            remove_padding = True

            # Damn, seems like some images like 7.1.2 iPhone3,2
            # need extra padding during encryption. Tihmstar,
            # you're right, WTF?

            # Ok, crypto needs extra padding, add it.

            to_encrypt += block2 + padding

            to_encrypt_len = len(to_encrypt)

            if not isAligned(to_encrypt_len, 16):
                paddedData = pad(16, to_encrypt)
                paddedSize = len(paddedData)

                paddingSize = paddedSize - to_encrypt_len + len(padding)
                padding = b'\x00' * paddingSize

                to_encrypt = paddedData

        # Start encryption

        if not isAligned(len(to_encrypt), 16):
            raise AlignmentError('Data to encrypt is not 16 aligned!')

        if self.image_encrypted:
            if not self.iv:
                raise MissingArgument('Iv missing!')

            if not self.key:
                raise MissingArgument('Key missing!')

            encrypted = doAES(True, self.aes_type, to_encrypt, self.iv, self.key)
        else:
            encrypted = to_encrypt

        if remove_padding:
            self.encrypted_truncate = len(padding)

        if not remove_padding and block2:
            encrypted += block2

            # iOS 10 is always 16 aligned
            if not self.image_encrypted :
                encryptedPadded = pad(16, encrypted)
                self.encrypted_truncate = len(encryptedPadded) - len(encrypted)
                encrypted = encryptedPadded

        return encrypted

    def verifySHSH(self):
        certData = self.extractCertificate()

        if certData is None:
            return

        pKey = extractPublicKeyFromDER(certData)

        shshRSAEncryptedSHA1 = self.extractSHSH()
        shshTagStart = self.getPositionOfTag(b'SHSH')

        dataToCheck = self.data[12:shshTagStart]
        isValid = doRSACheck(pKey, shshRSAEncryptedSHA1, dataToCheck)
        return isValid

    def getNestedImages(self):
        certData = self.extractCertificate()

        if certData is None:
            return

        nestedImages = extractNestedImages(certData)

        i = 0

        headData = getBufferAtIndex(nestedImages, i, self.img3_head_size)

        try:
            headInfo = self.readHead(i, headData)
        except BadMagic:
            # Assume 'cert' (not CERT) doesn't exist
            return

        i += self.img3_head_size

        tags = []

        while i != headInfo['fullSize']:
            try:
                tag = self.readTag(i, nestedImages)
            except BadMagic:
                raise
            else:
                tags.append(tag)
                i += tag['totalLength']

        return headInfo, tags

    def prepareKBAGS(self):
        kbags = self.getTagWithMagic(b'KBAG')

        prepared = []

        for kbag in kbags:
            kbagInfo = self.parseKBAGTag(kbag)

            buffer = kbagInfo['iv'] + kbagInfo['key']
            bufferSize = len(buffer)

            if not isAligned(bufferSize, 16):
                buffer = pad(16, buffer)
                bufferSize = len(buffer)

            prepared.append((kbagInfo['release'], buffer))

        return prepared

    def decryptKBAG(self, kbag, key):
        iv = b'\x00' * 16
        decryptedKbag = doAES(False, self.aes_type, kbag, iv, key)
        iv = getBufferAtIndex(decryptedKbag, 0, 16)
        key = getBufferAtIndex(decryptedKbag, 16, len(kbag) - self.aes_supported[self.aes_type])
        return iv, key


class Img3LZSS(Img3Crypt):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data, iv, key)

    def handleKernelData(self, data, kaslr=True):
        return LZSS(data, kaslr).go()


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

            if tag_magic in tag_ignore:
                continue

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
        for i, t in enumerate(self.tags):
            if t['magic'] != tag['magic']:
                continue

            self.tags[i] = tag
            break

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
            tag['pad'] = getBufferAtIndex(tag_data, tag['dataLength'], self.encrypted_truncate)

        self.replaceTag(tag)

    def removeTag(self, magic, removeAll=True):
        # TODO removeAll

        tags = []

        for tag in self.tags:
            if tag['magic'] == magic[::-1]:
                continue

            tags.append(tag)

        self.tags = tags
        self.updateHead()


class Img3File(Img3Modifier):
    def __init__(self, data, iv=None, key=None):
        super().__init__(data, iv, key)

    def do24KPWN(self, isN88=True):
        if self.ident != b'illb':
            raise IdentityError('24KPWN is only for LLB images!')

        kpwnSize = None
        dword = None
        shellcode = None
        bootstrap = None
        shellcodeOffset = KPWN_SHELLCODE_OFFSET
        bootstrapOffset = KPWN_BOOTSTRAP_OFFSET

        if isN88:
            kpwnSize = N88_24KPWN_SIZE
            dword = N88_SHELLCODE_ADDRESS
            shellcode = N88_SHELLCODE
            bootstrap = N88_BOOTSTRAP
        else:
            kpwnSize = N72_24KPWN_SIZE
            dword = N72_SHELLCODE_ADDRESS
            shellcode = N72_SHELLCODE
            bootstrap = N72_BOOTSTRAP

        if isN88:
            try:
                typeTag = self.getTagWithMagic(b'TYPE')[0]
            except TagNotFound:
                raise

            typeTagPadding = b'\x00' * len(typeTag['pad'])
            typeTag['pad'] = typeTagPadding
            self.replaceTag(typeTag)
        else:
            self.removeTag(b'TYPE')

        try:
            dataTag = self.getTagWithMagic(b'DATA')[0]
        except TagNotFound:
            raise

        dataTagData = bytearray(dataTag['data'])

        dataTagDataDWORD = getBufferAtIndex(dataTagData, 0, 4)
        dataTagData[:4] = dword
        dataTag['data'] = dataTagData

        self.removeTag(b'KBAG')

        try:
            certTag = self.getTagWithMagic(b'CERT')[0]
        except TagNotFound:
            raise

        certTagData = certTag['data'] + certTag['pad']

        pos = self.getPositionOfTag(b'CERT') + self.tag_head_size
        sizeToFill = kpwnSize - pos

        paddedData = bytearray(pad(sizeToFill, certTagData))

        if not isN88:
            shellcode = shellcode.replace(b'\xdf\xdb\x64\x80', dataTagDataDWORD)
        else:
            shellcode = shellcode.replace(b'\xAA\xBB\xCC\xDD', dataTagDataDWORD)

        shellcodeSize = len(N88_SHELLCODE)
        shellcodeStart = shellcodeOffset - pos
        paddedData[shellcodeStart:shellcodeStart+shellcodeSize] = shellcode

        bootstrapSize = len(bootstrap)
        bootstrapStart = bootstrapOffset - pos
        paddedData[bootstrapStart:bootstrapStart+bootstrapSize] = bootstrap

        newCertTag = self.makeTag(b'CERT', paddedData)
        self.replaceTag(newCertTag)

        if self.head['fullSize'] != kpwnSize:
            raise SizeError(f'LLB is not {kpwnSize} in size!')

        return self.updateImg3Data()

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

    def sign(self, shshBlobs):
        blob = None
        matches = {}

        for blobType in shshBlobs:
            bType = blobType.lower().encode()
            similarity = getSimilarityBetweenData(bType, self.ident)
            matches[blobType] = similarity

        bestMatch = max(matches.values())

        for bType in matches:
            if matches[bType] != bestMatch:
                continue

            print(f'Signing for: {bType}')

            blob = shshBlobs[bType]['Blob']
            break

        if not blob:
            raise MissingBlobType('Could not find correct blob!')

        newTagsSize = len(blob)
        i = 0
        newTags = []

        while i != newTagsSize:
            tag = self.readTag(i, blob)
            i += tag['totalLength']
            newTags.append(tag)

        shshTagIndex = 0

        for i, tag in enumerate(self.tags):
            if tag['magic'] != b'SHSH'[::-1]:
                continue

            shshTagIndex += i
            break

        tags = self.tags[:shshTagIndex]
        tags.extend(newTags)

        self.tags = tags
        self.updateHead()

        return self.updateImg3Data()
