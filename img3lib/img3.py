
from binascii import hexlify
from functools import partial
from itertools import zip_longest
from struct import pack, unpack

from binpatch.utils import getBufferAtIndex, replaceBufferAtIndex
from Crypto.Hash import SHA1

from .crypto import (AES_BLOCK_SIZE, AES_SIZES, GID_KEY_SIZE, IV_DEFAULT_KEY,
                     SHSH_KEY_SIZE, doAES, doRSACheck)
from .der import (decodeDER, extractNestedImages, extractPublicKeyFromDER,
                  extractSHA1HashesFromAPTicket)
from .kernel import LZSS_SIGNATURE, MACHO_MAGIC, compress, decompress
from .kpwn import (KPWN_BOOTSTRAP_OFFSET, KPWN_SHELLCODE_OFFSET,
                   N72_24KPWN_SIZE, N72_BOOTSTRAP, N72_SHELLCODE,
                   N72_SHELLCODE_ADDRESS, N72_SHELLCODE_DWORD_INDEX,
                   N88_24KPWN_SIZE, N88_BOOTSTRAP, N88_SHELLCODE,
                   N88_SHELLCODE_ADDRESS, N88_SHELLCODE_DWORD_INDEX)
from .types import img3, img3tag, kbag
from .utils import appendPaddingToData, initPadding

IMG3_MAGIC = b'Img3'

IMG3_HEAD_SIZE = 20
TAG_HEAD_SIZE = 12
KBAG_HEAD_SIZE = 8

IMG3_MAGIC_SIZE = 4
IMG3_IDENT_SIZE = 4
TAG_MAGIC_SIZE = 4

KBAG_CRYPT_STATES = {
    1: 'Production',
    2: 'Development'
}

TAGS = (
    b'VERS', b'SEPO',
    b'SDOM', b'PROD',
    b'CHIP', b'BORD',
    b'KBAG', b'SHSH',
    b'CERT', b'ECID',
    b'TYPE', b'DATA',
    b'NONC', b'CEPO',
    b'OVRD', b'RAND',
    b'SALT',
)

TYPES = (
    b'krnl', b'rdsk',
    b'bat1', b'chg1',
    b'illb', b'batF',
    b'nsrv', b'chg0',
    b'dtre', b'glyC',
    b'bat0', b'logo',
    b'ibot', b'glyP',
    b'recm', b'ibec',
    b'ibss', b'cert',
    b'diag'
)

SEPOS = (
    1, 2, 3,
    4, 5, 16,
    17
)

BORDS = (
    0, 2, 4,
    6, 8, 10,
    14
)

CHIPS = (
    0x8720, 0x8900, 0x8920, 0x8922,
    0x8930, 0x8940, 0x8942, 0x8945,
    0x8947, 0x8950, 0x8955
)


def initImg3Tag() -> img3tag:
    return img3tag(b'', 0, 0, b'', b'')


def readTagHead(data: bytes) -> img3tag:
    if len(data) < TAG_HEAD_SIZE:
        raise ValueError(f'Data must be at least {TAG_HEAD_SIZE} bytes!')

    headData = getBufferAtIndex(data, 0, TAG_HEAD_SIZE)
    magic, totalSize, dataSize = unpack('<4s2I', headData)

    tagObj = initImg3Tag()
    tagObj.magic = magic
    tagObj.totalSize = totalSize
    tagObj.dataSize = dataSize

    return tagObj


def getTagPaddingSize(tag: img3tag) -> int:
    return tag.totalSize - tag.dataSize - TAG_HEAD_SIZE


def readTag(data: bytes) -> img3tag:
    if len(data) < TAG_HEAD_SIZE:
        raise ValueError(f'Data must be at least {TAG_HEAD_SIZE} bytes!')

    tag = readTagHead(data)
    tagMagicReversed = tag.magic[::-1]

    if tagMagicReversed not in TAGS:
        raise ValueError(f'Unknown tag magic: {tagMagicReversed.decode()}')

    tag.data = getBufferAtIndex(data, TAG_HEAD_SIZE, tag.dataSize)
    paddingSize = getTagPaddingSize(tag)

    if paddingSize >= 1:
        tag.padding = getBufferAtIndex(data, TAG_HEAD_SIZE + tag.dataSize, paddingSize)

    return tag


def initImg3() -> img3:
    return img3(b'', 0, 0, 0, b'', [])


def readImg3Head(data: bytes) -> img3:
    if len(data) < IMG3_HEAD_SIZE:
        raise ValueError(f'Data must be at least {IMG3_HEAD_SIZE} bytes!')

    headData = getBufferAtIndex(data, 0, IMG3_HEAD_SIZE)
    magic, fullSize, sizeNoPack, sigCheckArea, ident = unpack('<4s3I4s', headData)

    img3Obj = initImg3()
    img3Obj.magic = magic
    img3Obj.fullSize = fullSize
    img3Obj.sizeNoPack = sizeNoPack
    img3Obj.sigCheckArea = sigCheckArea
    img3Obj.ident = ident

    return img3Obj


def readImg3(data: bytes) -> img3:
    if len(data) < IMG3_HEAD_SIZE:
        raise ValueError(f'Data must be at least {IMG3_HEAD_SIZE} bytes!')

    img3Obj = readImg3Head(data)
    img3MagicReversed = img3Obj.magic[::-1]

    if img3MagicReversed != IMG3_MAGIC:
        raise ValueError(f'This is not an Img3 file! Expected magic {IMG3_MAGIC} but got {img3MagicReversed}!')

    identReversed = img3Obj.ident[::-1]

    if identReversed not in TYPES:
        raise ValueError(f'{identReversed.decode()} is not a valid type!')

    i = IMG3_HEAD_SIZE
    fullSize = img3Obj.fullSize

    while i in range(fullSize):
        tagData = getBufferAtIndex(data, i, fullSize - i)
        tag = readTag(tagData)
        img3Obj.tags.append(tag)
        i += tag.totalSize

    if i != fullSize:
        raise ValueError(f'Index error. Expected {fullSize}, got {i}!')

    return img3Obj


def tagExistsAtIndex(img3Obj: img3, magic: bytes) -> list[int]:
    if len(magic) != TAG_MAGIC_SIZE:
        raise ValueError(f'Magic must be {TAG_MAGIC_SIZE} bytes!')

    if magic not in TAGS:
        raise ValueError(f'{magic.decode()} is not a valid tag!')

    matches = []

    if not img3Obj.tags:
        return matches

    for i, tag in enumerate(img3Obj.tags):
        tagMagicReversed = tag.magic[::-1]

        if tagMagicReversed != magic:
            continue

        matches.append(i)

    return matches


def getTagWithMagic(img3Obj: img3, magic: bytes) -> list[img3tag]:
    if len(magic) != TAG_MAGIC_SIZE:
        raise ValueError(f'Magic must be {TAG_MAGIC_SIZE} bytes!')

    if magic not in TAGS:
        raise ValueError(f'Unknown tag magic: {magic.decode()}!')

    tagIndexes = tagExistsAtIndex(img3Obj, magic)

    if not tagIndexes:
        return tagIndexes

    return [img3Obj.tags[i] for i in tagIndexes]


def initKbag() -> kbag:
    return kbag(0, 0, b'', b'')


def parseKBAGHead(data: bytes) -> kbag:
    if len(data) < KBAG_HEAD_SIZE:
        raise ValueError(f'Data must be at least {KBAG_HEAD_SIZE} bytes!')

    headData = getBufferAtIndex(data, 0, KBAG_HEAD_SIZE)
    cryptState, aesType = unpack('<2I', headData)

    kbagObj = initKbag()
    kbagObj.cryptState = cryptState
    kbagObj.aesType = aesType

    return kbagObj


def parseKBAG(kbagTag: img3tag) -> kbag:
    kbagObj = parseKBAGHead(kbagTag.data)

    if kbagObj.cryptState not in KBAG_CRYPT_STATES:
        raise ValueError(f'Unknown cryptState: {kbagObj.cryptState}!')

    if kbagObj.aesType not in AES_SIZES:
        raise ValueError(f'Unknown AES: {kbagObj.aesType}!')

    keySize = AES_SIZES.get(kbagObj.aesType)

    if keySize is None:
        raise ValueError(f'Unknown AES key size: {keySize}')

    kbagObj.iv = getBufferAtIndex(kbagTag.data, KBAG_HEAD_SIZE, AES_BLOCK_SIZE)
    kbagObj.key = getBufferAtIndex(kbagTag.data, KBAG_HEAD_SIZE + AES_BLOCK_SIZE, keySize)

    return kbagObj


def printKBAG(kbagTag: img3tag) -> None:
    kbagObj = parseKBAG(kbagTag)
    cryptState = KBAG_CRYPT_STATES.get(kbagObj.cryptState)

    if cryptState is None:
        raise ValueError(f'Unknown cryptState: {kbagObj.cryptState}')

    print(f'CryptState: {cryptState}')
    print(f'AES: {kbagObj.aesType}')
    print(f'IV: {hexlify(kbagObj.iv).decode()}')
    print(f'Key: {hexlify(kbagObj.key).decode()}')


def makeTag(magic: bytes, data: bytes) -> img3tag:
    if len(magic) != TAG_MAGIC_SIZE:
        raise ValueError(f'Magic must be {TAG_MAGIC_SIZE} bytes!')

    if magic not in TAGS:
        raise ValueError(f'Unknown tag magic: {magic.decode()}')

    dataSize = len(data)

    align = 4 if magic != b'DATA' else 16
    paddedData = appendPaddingToData(align, data)
    paddedDataSize = len(paddedData)
    paddingSize = paddedDataSize - dataSize

    tag = initImg3Tag()
    tag.magic = magic[::-1]
    tag.totalSize = TAG_HEAD_SIZE + paddedDataSize
    tag.dataSize = dataSize
    tag.data = getBufferAtIndex(paddedData, 0, dataSize)

    if paddingSize >= 1:
        tag.padding = getBufferAtIndex(paddedData, dataSize, paddingSize)

    return tag


def isDataTagPaddingZeroed(dataTag: img3tag) -> bool:
    if dataTag.magic[::-1] != b'DATA':
        raise ValueError('Tag must be of type: DATA!')

    padSize = getTagPaddingSize(dataTag)
    zeroedPadding = initPadding(padSize)
    isPaddingZeroed = dataTag.padding == zeroedPadding

    return isPaddingZeroed


def img3Decrypt(dataTag: img3tag, aes: int | None, iv: bytes | None, key: bytes | None) -> tuple[img3tag, bool]:
    dataTagMagic = b'DATA'

    if dataTag.magic[::-1] != dataTagMagic:
        raise ValueError('Tag must be of type: DATA!')

    block1Size = dataTag.dataSize & ~0xF
    block2Size = dataTag.dataSize & 0xF

    block1Data = getBufferAtIndex(dataTag.data, 0, block1Size)
    block2Data = getBufferAtIndex(dataTag.data, block1Size, block2Size) if block2Size >= 1 else b''

    decryptBuffer = block1Data
    isPaddingZeroed = isDataTagPaddingZeroed(dataTag)

    if not isPaddingZeroed:
        # Padding isn't zeroed, which means it's included during decryption
        decryptBuffer += block2Data + dataTag.padding

    if aes is not None and iv and key:
        # Image is likely a non-iOS 10 image
        decryptBuffer = doAES(False, aes, decryptBuffer, iv, key)

    if isPaddingZeroed:
        # Padding is zeroed, only block1Size was encrypted
        decryptBuffer += block2Data
    else:
        # Padding wasn't zeroed, which means we have to remove decrypted padding
        decryptBuffer = getBufferAtIndex(decryptBuffer, 0, dataTag.dataSize)

    newDataTag = makeTag(dataTagMagic, decryptBuffer)
    return newDataTag, isPaddingZeroed


def handleKernelData(dataTag: img3tag, kASLRSupported: bool = False) -> img3tag:
    KERNEL_COMPRESS_MODE = {
        MACHO_MAGIC: partial(compress, kASLRSupported=kASLRSupported),
        LZSS_SIGNATURE: decompress
    }

    magic = getBufferAtIndex(dataTag.data, 0, 4)

    if magic not in KERNEL_COMPRESS_MODE:
        raise ValueError(f'Unknown kernel magic: {magic.decode()}')

    mode = KERNEL_COMPRESS_MODE.get(magic)

    if mode is None:
        raise ValueError('Cannot determine compress mode!')

    newData = mode(dataTag.data)
    newDataTag = makeTag(b'DATA', newData)

    return newDataTag


def img3Encrypt(dataTag: img3tag, aes: int | None, iv: bytes | None, key: bytes | None, paddingWasZeroed: bool = False) -> img3tag:
    dataTagMagic = b'DATA'

    if dataTag.magic[::-1] != dataTagMagic:
        raise ValueError('Tag must be of type: DATA!')

    block1Size = dataTag.dataSize & ~0xF
    block2Size = dataTag.dataSize & 0xF
    block1Data = getBufferAtIndex(dataTag.data, 0, block1Size)
    block2Data = getBufferAtIndex(dataTag.data, block1Size, block2Size) if block2Size >= 1 else b''
    encryptBuffer = block1Data

    if not paddingWasZeroed:
        encryptBuffer += block2Data + dataTag.padding

    # Ensure we pad the encrypt buffer
    encryptBuffer = appendPaddingToData(AES_BLOCK_SIZE, encryptBuffer)

    if aes is not None and iv and key:
        encryptBuffer = doAES(True, aes, encryptBuffer, iv, key)

    padding = b''
    encryptBufferSize = len(encryptBuffer)

    if paddingWasZeroed:
        encryptBuffer += block2Data
    else:
        paddingSize = len(dataTag.padding)

        if paddingSize >= 1:
            padding = getBufferAtIndex(encryptBuffer, encryptBufferSize - paddingSize, paddingSize)
            encryptBuffer = getBufferAtIndex(encryptBuffer, 0, encryptBufferSize - paddingSize)

    newDataTag = makeTag(dataTagMagic, encryptBuffer)

    if padding:
        if len(newDataTag.padding) != len(padding):
            raise ValueError(f'Expected padding size {len(newDataTag.padding)}, got {len(padding)}!')

        newDataTag.padding = padding

    return newDataTag


def updateImg3Head(img3Obj: img3) -> img3:
    i = 0
    sigCheckArea = 0

    for tag in img3Obj.tags:
        i += tag.totalSize

        # TODO: This will include anything after these two.
        # This means anything at the end will be include in
        # the size calculations. I've only ever seen objects
        # where SHSH and CERT are at the end. Check this!

        if tag.magic[::-1] in (b'SHSH', b'CERT'):
            continue

        sigCheckArea += tag.totalSize

    img3Obj.fullSize = i + IMG3_HEAD_SIZE
    img3Obj.sizeNoPack = i
    img3Obj.sigCheckArea = sigCheckArea

    return img3Obj


def replaceTagInImg3Obj(img3Obj: img3, newTag: img3tag) -> img3:
    tags = img3Obj.tags.copy()

    for i, tag in enumerate(img3Obj.tags):
        if tag.magic != newTag.magic:
            continue

        tags[i] = newTag
        break

    img3Obj.tags = tags
    return updateImg3Head(img3Obj)


def img3ToBytes(img3Obj: img3) -> bytes:
    img3HeadData = pack('<4s3I4s', img3Obj.magic, img3Obj.fullSize, img3Obj.sizeNoPack, img3Obj.sigCheckArea, img3Obj.ident)
    tagsData = b''

    if img3Obj.tags:
        for tag in img3Obj.tags:
            tagsData += pack('<4s2I', tag.magic, tag.totalSize, tag.dataSize) + tag.data + tag.padding

    img3Data = img3HeadData + tagsData

    # TODO Make sure img3's with no tags are valid here
    if len(img3Data) != img3Obj.fullSize:
        raise ValueError(f'Img3 buffer is not of size: {img3Obj.fullSize}!')

    return img3Data


def findDifferencesBetweenTwoImg3s(img3Obj1: img3, img3Obj2: img3):
    if img3Obj1.magic != img3Obj2.magic:
        print(f'Magic: {img3Obj1.magic.decode()}, {img3Obj2.magic.decode()}')

    if img3Obj1.fullSize != img3Obj2.fullSize:
        print(f'Fullsize: {img3Obj1.fullSize}, {img3Obj2.fullSize}')

    if img3Obj1.sizeNoPack != img3Obj2.sizeNoPack:
        print(f'SizeNoPack: {img3Obj1.sizeNoPack}, {img3Obj2.sizeNoPack}')

    if img3Obj1.sigCheckArea != img3Obj2.sigCheckArea:
        print(f'SigCheckArea: {img3Obj1.sigCheckArea}, {img3Obj2.sigCheckArea}')

    if img3Obj1.ident != img3Obj2.ident:
        print(f'Ident: {img3Obj1.ident.decode()}, {img3Obj2.ident.decode()}')

    if not img3Obj1.tags:
        raise ValueError('Img3 1 does not have any tags!')

    if not img3Obj2.tags:
        raise ValueError('Img3 2 does not have any tags!')

    for tag1, tag2 in zip_longest(img3Obj1.tags, img3Obj2.tags):
        if tag1 and tag2 is None:
            print(f'\tMagic: {tag1.magic.decode()}, {None}')
            print(f'\tTotal size: {tag1.totalSize}, {None}')
            print(f'\tData size: {tag1.dataSize}, {None}')
            print(f'\tPadding size: {getTagPaddingSize(tag1)}, {None}')
            continue

        elif tag1 is None and tag2:
            print(f'\tMagic: {None}, {tag2.magic.decode()}')
            print(f'\tTotal size: {None}, {tag2.totalSize}')
            print(f'\tData size: {None}, {tag2.dataSize}')
            print(f'\tPadding size: {None}, {getTagPaddingSize(tag2)}')
            continue

        info = {
            'Magic': (tag1.magic, tag2.magic),
            'Total size': (tag1.totalSize, tag2.totalSize),
            'Data size': (tag1.dataSize, tag2.dataSize),
            'Padding Size': (getTagPaddingSize(tag1), getTagPaddingSize(tag2))
        }

        differences = []

        for i, value in enumerate(info):
            values = info.get(value)

            if values is None:
                raise ValueError(f'No value: {value}')

            valuesDiffer = True if len(set(values)) > 1 else False

            if not valuesDiffer:
                continue

            differences.append(value)

        if not differences:
            continue

        print(f'Magic: {tag1.magic.decode()}')

        for difference in differences:
            values = info.get(difference)

            if values is None:
                raise ValueError(f'No value: {difference}')

            value1, value2 = values

            if difference == 'Magic':
                value1 = value1.decode()
                value2 = value2.decode()

            print(f'\t{difference}: {value1}, {value2}')


def printImg3Info(img3Obj: img3) -> None:
    print(f'Magic: {img3Obj.magic.decode()}')
    print(f'Fullsize: {img3Obj.fullSize}')
    print(f'SizeNoPack: {img3Obj.sizeNoPack}')
    print(f'SigCheckArea: {img3Obj.sigCheckArea}')
    print(f'Ident: {img3Obj.ident.decode()}')

    if img3Obj.tags:
        for tag in img3Obj.tags:
            print(f'Magic: {tag.magic.decode()}')
            print(f'Totalsize: {tag.totalSize}')
            print(f'Datasize: {tag.dataSize}')
            print(f'Padsize: {getTagPaddingSize(tag)}')


def getTagOffsetInImg3(img3Obj: img3, magic: bytes) -> int:
    if len(magic) != TAG_MAGIC_SIZE:
        raise ValueError(f'Magic must be {TAG_MAGIC_SIZE} bytes!')

    if magic not in TAGS:
        raise ValueError(f'Unknown magic: {magic.decode()}!')

    i = IMG3_HEAD_SIZE
    # FIXME: Return 0 if no tags. We will know that there aren't
    # any tags if the at least the offset is <= IMG3_HEAD_SIZE

    for tag in img3Obj.tags:
        if tag.magic == magic:
            break

        i += tag.totalSize

    if i not in range(img3Obj.fullSize + 1):
        raise ValueError(f'Bad index: {i}')

    return i


def getImg3SHA1Buffer(img3Obj: img3) -> bytes:
    img3Bytes = img3ToBytes(img3Obj)
    # TODO Replace sigCheckArea + 8 with getTagOffsetInImg3(img3Obj, b'SHSH')
    sha1Buffer = getBufferAtIndex(img3Bytes, 12, img3Obj.sigCheckArea + 8)
    return sha1Buffer


# TODO: Figure out why this seems to produce false values in certain objects during testing
def verifySHSH(img3Obj: img3) -> bool | None:
    shshTag = getTagWithMagic(img3Obj, b'SHSH')

    if not shshTag:
        return None

    if len(shshTag[0].data) != SHSH_KEY_SIZE:
        raise ValueError(f'SHSH data size mismatch. Got {len(shshTag[0].data)}, expected {SHSH_KEY_SIZE}!')

    certTag = getTagWithMagic(img3Obj, b'CERT')

    if not certTag:
        return None

    publicKey = extractPublicKeyFromDER(certTag[0].data)
    img3SHA1Data = getImg3SHA1Buffer(img3Obj)
    isSHA1HashValid = doRSACheck(publicKey, shshTag[0].data, img3SHA1Data)

    return isSHA1HashValid


def removeTagFromImg3(img3Obj: img3, magic: bytes, removeAll: bool = False) -> img3:
    if len(magic) != TAG_MAGIC_SIZE:
        raise ValueError(f'Magic must be {TAG_MAGIC_SIZE} bytes!')

    if magic not in TAGS:
        raise ValueError(f'Unknown magic: {magic.decode()}!')

    tagIndexes = tagExistsAtIndex(img3Obj, magic)

    if not tagIndexes:
        return img3Obj

    if not removeAll:
        tagIndexes = tagIndexes[:1]

    tags = []

    for i, tag in enumerate(img3Obj.tags):
        if i in tagIndexes:
            continue

        tags.append(tag)

    img3Obj.tags = tags
    return updateImg3Head(img3Obj)


def make24KPWNLLB(img3Obj: img3, isN72: bool, isN88: bool) -> img3:
    if isN72 and isN88:
        raise ValueError('Both device conditions ARE set!')

    if not isN72 and not isN88:
        raise ValueError('Both device condidtions are NOT set!')

    newImg3 = None
    shellcodeOffset = KPWN_SHELLCODE_OFFSET
    bootstrapOffset = KPWN_BOOTSTRAP_OFFSET
    kpwnSize = N72_24KPWN_SIZE if isN72 else N88_24KPWN_SIZE
    dword = N72_SHELLCODE_ADDRESS if isN72 else N88_SHELLCODE_ADDRESS
    shellcode = N72_SHELLCODE if isN72 else N88_SHELLCODE
    bootstrap = N72_BOOTSTRAP if isN72 else N88_BOOTSTRAP
    dwordIndex = N72_SHELLCODE_DWORD_INDEX if isN72 else N88_SHELLCODE_DWORD_INDEX

    typeTagMagic = b'TYPE'

    if isN88:
        typeTag = getTagWithMagic(img3Obj, typeTagMagic)

        if not typeTag:
            raise ValueError('This image does not contain a TYPE tag!')

        typeTag[0].padding = initPadding(getTagPaddingSize(typeTag[0]))
        newImg3 = replaceTagInImg3Obj(img3Obj, typeTag[0])
    else:
        newImg3 = removeTagFromImg3(img3Obj, typeTagMagic, True)

    dataTag = getTagWithMagic(newImg3, b'DATA')

    if not dataTag:
        raise ValueError('This image does not contain a DATA tag!')

    dataTagDword = getBufferAtIndex(dataTag[0].data, 0, 4)
    dataTag[0].data = dword + getBufferAtIndex(dataTag[0].data, 4, dataTag[0].dataSize - 4)

    newImg3 = removeTagFromImg3(newImg3, b'KBAG', True)

    certTagMagic = b'CERT'
    certTag = getTagWithMagic(newImg3, certTagMagic)

    if not certTag:
        raise ValueError('This image does not contain a CERT tag!')

    certTagData = certTag[0].data + certTag[0].padding
    certTagDataStartPos = getTagOffsetInImg3(img3Obj, certTagMagic) + TAG_HEAD_SIZE
    sizeToFill = kpwnSize - certTagDataStartPos
    certTagDataPadded = bytearray(appendPaddingToData(sizeToFill, certTagData))

    shellcode = replaceBufferAtIndex(bytearray(shellcode), dataTagDword, dwordIndex, 4)

    shellcodeSize = len(shellcode)
    shellcodeStart = shellcodeOffset - certTagDataStartPos
    certTagDataPadded = replaceBufferAtIndex(certTagDataPadded, bytes(shellcode), shellcodeStart, shellcodeSize)

    bootstrapSize = len(bootstrap)
    bootstrapStart = bootstrapOffset - certTagDataStartPos
    certTagDataPadded = replaceBufferAtIndex(certTagDataPadded, bootstrap, bootstrapStart, bootstrapSize)

    newCertTag = makeTag(certTagMagic, bytes(certTagDataPadded))
    newImg3 = replaceTagInImg3Obj(newImg3, newCertTag)

    if img3Obj.fullSize != kpwnSize:
        raise ValueError(f'LLB is not of size: {kpwnSize}!')

    return newImg3


def appendTagInImg3(img3Obj: img3, tag: img3tag) -> img3:
    img3Obj.tags.append(tag)
    return updateImg3Head(img3Obj)


def signImg3(img3Obj: img3, blobData: dict, manifestData: dict) -> img3:
    if not blobData:
        raise ValueError('Blob data is empty!')

    if not manifestData:
        raise ValueError('Manifest data is empty!')

    manifest = manifestData['BuildIdentities'][0]['Manifest']
    img3SHA1 = None
    imageName = None

    for name in manifest:
        sha1Digest = manifest[name].get('Digest')

        if sha1Digest is None:
            continue

        sha1Buffer = getImg3SHA1Buffer(img3Obj)
        bufferSHA1 = SHA1.new(sha1Buffer)

        if sha1Digest != bufferSHA1.digest():
            continue

        img3SHA1 = bufferSHA1.hexdigest()
        imageName = name
        break

    if img3SHA1 is None:
        raise ValueError('Unable to find digest!')

    if imageName is None:
        raise ValueError('Image name is empty!')

    decoded = decodeDER(blobData['APTicket'])
    sha1Hashes = extractSHA1HashesFromAPTicket(decoded)

    sha1FoundInApTicket = False

    for sha1Hash in sha1Hashes:
        if img3SHA1 != sha1Hash:
            continue

        sha1FoundInApTicket = True
        break

    if not sha1FoundInApTicket:
        raise ValueError('Could not find SHA1 in ApTicket!')

    imageBlob = blobData.get(imageName)

    if imageBlob is None:
        raise ValueError(f'{imageName} is missing in blob data!')

    imageBlobData = imageBlob['Blob']
    blobDataSize = len(imageBlobData)

    newImg3 = removeTagFromImg3(img3Obj, b'ECID', True)
    newImg3 = removeTagFromImg3(img3Obj, b'SHSH', True)
    newImg3 = removeTagFromImg3(img3Obj, b'CERT', True)

    i = 0
    tags = []

    while i in range(blobDataSize):
        buffer = getBufferAtIndex(imageBlobData, i, blobDataSize - i)
        tag = readTag(buffer)
        tags.append(tag)
        i += tag.totalSize

    if i != blobDataSize:
        raise ValueError('Error occurred during tag reading!')

    for tag in tags:
        newImg3 = appendTagInImg3(newImg3, tag)

    return newImg3


def getNestedImageInCERT(certTag: img3tag) -> img3 | None:
    magicReversed = certTag.magic[::-1]

    if magicReversed != b'CERT':
        raise ValueError(f'Incorrect tag magic! Got {magicReversed.decode()}!')

    if not certTag.data:
        raise ValueError('CERT data is empty!')

    derData = decodeDER(certTag.data)
    nestedData = extractNestedImages(derData)
    nestedImage = None

    try:
        nestedImage = readImg3(nestedData)
    except ValueError:
        pass

    return nestedImage


def decryptKBAG(kbagObj: kbag, gidKey: bytes) -> kbag:
    if len(gidKey) != GID_KEY_SIZE:
        raise ValueError(f'GIDKey must be {GID_KEY_SIZE} bytes!')

    cryptBuffer = kbagObj.iv + kbagObj.key
    decryptedBuffer = doAES(False, kbagObj.aesType, cryptBuffer, IV_DEFAULT_KEY, gidKey)

    keySize = AES_SIZES.get(kbagObj.aesType)

    if keySize is None:
        raise ValueError(f'Unknown AES type: {kbagObj.aesType}')

    kbagObj.iv = getBufferAtIndex(decryptedBuffer, 0, AES_BLOCK_SIZE)
    kbagObj.key = getBufferAtIndex(decryptedBuffer, AES_BLOCK_SIZE, keySize)

    return kbagObj


def encryptKBAG(kbagObj: kbag, gidKey: bytes) -> kbag:
    if len(gidKey) != GID_KEY_SIZE:
        raise ValueError(f'GIDKey must be {GID_KEY_SIZE} bytes!')

    cryptBuffer = kbagObj.iv + kbagObj.key
    encryptedBuffer = doAES(True, kbagObj.aesType, cryptBuffer, IV_DEFAULT_KEY, gidKey)

    keySize = AES_SIZES.get(kbagObj.aesType)

    if keySize is None:
        raise ValueError(f'Unknown AES type: {kbagObj.aesType}')

    kbagObj.iv = getBufferAtIndex(encryptedBuffer, 0, AES_BLOCK_SIZE)
    kbagObj.key = getBufferAtIndex(encryptedBuffer, AES_BLOCK_SIZE, keySize)

    return kbagObj
