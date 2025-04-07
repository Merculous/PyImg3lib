
from binascii import hexlify
from io import SEEK_END, SEEK_SET, BytesIO
from struct import pack, unpack

from binpatch.io import getSizeOfIOStream
from binpatch.utils import getBufferAtIndex, replaceBufferAtIndex

from .der import extractNestedImages, extractPublicKeyFromDER
from .kpwn import (KPWN_BOOTSTRAP_OFFSET, KPWN_SHELLCODE_OFFSET,
                   N72_24KPWN_SIZE, N72_BOOTSTRAP, N72_SHELLCODE,
                   N72_SHELLCODE_ADDRESS, N88_24KPWN_SIZE, N88_BOOTSTRAP,
                   N88_SHELLCODE, N88_SHELLCODE_ADDRESS)
from .lzsscode import compress, decompress
from .types import img3, img3tag, kbag
from .utils import doAES, doRSACheck, isAligned, pad

IMG3_MAGIC = b'Img3'

IMG3_HEAD_SIZE = 20
TAG_HEAD_SIZE = 12

KBAG_CRYPT_STATE_PRODUCTION = 1
KBAG_CRYPT_STATE_DEVELOPMENT = 2

TAGS = (
    b'VERS', b'SEPO', b'SDOM',
    b'PROD', b'CHIP', b'BORD',
    b'KBAG', b'SHSH', b'CERT',
    b'ECID', b'TYPE', b'DATA',
    b'NONC', b'CEPO', b'OVRD',
    b'RAND', b'SALT'
)

TYPES = (
    b'krnl', b'rdsk', b'bat1',
    b'chg1', b'illb', b'batF',
    b'nsrv', b'chg0', b'dtre',
    b'glyC', b'bat0', b'logo',
    b'ibot', b'glyP', b'recm',
    b'ibec', b'ibss', b'cert',
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

AES_SIZES = {
    128: 16,
    192: 24,
    256: 32
}

def initTag() -> img3tag:
    return img3tag(BytesIO(), 0, 0, BytesIO(), BytesIO())


def initImg3() -> img3:
    return img3(BytesIO(), 0, 0, 0, BytesIO(), [])


def readTagHead(data: BytesIO) -> img3tag:
    if not isinstance(data, BytesIO):
        raise TypeError

    data.seek(0, SEEK_SET)

    tagHeadData = getBufferAtIndex(data, 0, TAG_HEAD_SIZE)
    tagHeadUnpacked = unpack('<4s2I', tagHeadData.getvalue())

    tag = initTag()
    tag.magic.seek(0, SEEK_SET)
    tag.magic.write(tagHeadUnpacked[0])
    tag.magic.seek(0, SEEK_SET)

    tag.totalSize = tagHeadUnpacked[1]
    tag.dataSize = tagHeadUnpacked[2]

    return tag


def getTagMagic(tag: img3tag) -> BytesIO:
    if not isinstance(tag, img3tag):
        raise TypeError

    if not isinstance(tag.magic, BytesIO):
        raise TypeError

    if not tag.magic:
        raise TypeError('Tag magic is empty!')

    return BytesIO(tag.magic.getvalue()[::-1])


def getTagTotalSize(tag: img3tag) -> int:
    if not isinstance(tag, img3tag):
        raise TypeError

    if not isinstance(tag.totalSize, int):
        raise TypeError

    return tag.totalSize


def getTagDataSize(tag: img3tag) -> int:
    if not isinstance(tag, img3tag):
        raise TypeError

    if not isinstance(tag.dataSize, int):
        raise TypeError

    return tag.dataSize


def readTag(data: BytesIO) -> img3tag:
    if not isinstance(data, BytesIO):
        raise TypeError

    data.seek(0, SEEK_SET)
    tag = readTagHead(data)

    if not isinstance(tag.magic, BytesIO):
        raise TypeError

    if not isinstance(tag.totalSize, int):
        raise TypeError

    if not isinstance(tag.dataSize, int):
        raise TypeError

    if not isinstance(tag.data, BytesIO):
        raise TypeError

    if not isinstance(tag.padding, BytesIO):
        raise TypeError

    tagMagic = getTagMagic(tag).getvalue()

    if tagMagic not in TAGS:
        raise ValueError(f'Unknown tag magic: {tagMagic}')

    tag.data = getBufferAtIndex(data, TAG_HEAD_SIZE, tag.dataSize)

    paddingSize = tag.totalSize - tag.dataSize - TAG_HEAD_SIZE

    if paddingSize >= 1:
        tag.padding = getBufferAtIndex(data, TAG_HEAD_SIZE + tag.dataSize, paddingSize)

    return tag


def getTagData(tag: img3tag) -> BytesIO:
    if not isinstance(tag, img3tag):
        raise TypeError

    if not isinstance(tag.data, BytesIO):
        raise TypeError

    return tag.data


def getTagPadding(tag: img3tag) -> BytesIO:
    if not isinstance(tag, img3tag):
        raise TypeError

    if not isinstance(tag.padding, BytesIO):
        raise TypeError

    return tag.padding


def readImg3Head(data: BytesIO) -> img3:
    if not isinstance(data, BytesIO):
        raise TypeError

    img3HeadData = getBufferAtIndex(data, 0, IMG3_HEAD_SIZE)
    img3Unpacked = unpack('<4s3I4s', img3HeadData.getvalue())

    img3Obj = initImg3()
    img3Obj.magic.seek(0, SEEK_SET)
    img3Obj.magic.write(img3Unpacked[0])
    img3Obj.magic.seek(0, SEEK_SET)

    img3Obj.fullSize = img3Unpacked[1]
    img3Obj.sizeNoPack = img3Unpacked[2]
    img3Obj.sigCheckArea = img3Unpacked[3]

    img3Obj.ident.seek(0, SEEK_SET)
    img3Obj.ident.write(img3Unpacked[4])
    img3Obj.ident.seek(0, SEEK_SET)

    return img3Obj


def getImg3Magic(img3Obj: img3) -> BytesIO:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.magic, BytesIO):
        raise TypeError

    return BytesIO(img3Obj.magic.getvalue()[::-1])


def getImg3FullSize(img3Obj: img3) -> int:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.fullSize, int):
        raise TypeError

    return img3Obj.fullSize


def getImg3SizeNoPack(img3Obj: img3) -> int:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.sizeNoPack, int):
        raise TypeError

    return img3Obj.sizeNoPack


def getImg3SigCheckArea(img3Obj: img3) -> int:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.sigCheckArea, int):
        raise TypeError

    return img3Obj.sigCheckArea


def getImg3Ident(img3Obj: img3) -> BytesIO:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.ident, BytesIO):
        raise TypeError

    return BytesIO(img3Obj.ident.getvalue()[::-1])


def readImg3(data: BytesIO) -> img3:
    if not isinstance(data, BytesIO):
        raise TypeError

    dataSize = getSizeOfIOStream(data)
    img3Obj = readImg3Head(data)

    if not isinstance(img3Obj.magic, BytesIO):
        raise TypeError

    if not isinstance(img3Obj.fullSize, int):
        raise TypeError

    if not isinstance(img3Obj.sizeNoPack, int):
        raise TypeError

    if not isinstance(img3Obj.sigCheckArea, int):
        raise TypeError

    if not isinstance(img3Obj.ident, BytesIO):
        raise TypeError

    if getImg3Magic(img3Obj).getvalue() != IMG3_MAGIC:
        raise ValueError('This is not an Img3 file!')

    if img3Obj.fullSize != dataSize:
        raise ValueError(f'Size mismatch. Expected {dataSize}, got {img3Obj.fullSize}')

    if img3Obj.sizeNoPack != dataSize - IMG3_HEAD_SIZE:
        raise ValueError(f'Size mismatch. Expected {dataSize-IMG3_HEAD_SIZE}, got {img3Obj.sizeNoPack}')

    if getImg3Ident(img3Obj).getvalue() not in TYPES:
        raise ValueError(f'{img3Obj.ident} is not a valid type!')

    img3Obj.tags = []
    i = IMG3_HEAD_SIZE

    while i in range(img3Obj.fullSize):
        tagData = getBufferAtIndex(data, i, img3Obj.fullSize - i)
        tag = readTag(tagData)

        if not isinstance(tag, img3tag):
            raise TypeError

        img3Obj.tags.append(tag)
        i += getTagTotalSize(tag)

    if i != img3Obj.fullSize:
        raise ValueError(f'Index error. Expected {img3Obj.fullSize}, got {i}!')

    return img3Obj


def tagExists(img3Obj: img3, magic: BytesIO) -> list[int]:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(magic, BytesIO):
        raise TypeError

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    matches = []

    if not img3Obj.tags:
        return matches

    for i, tag in enumerate(img3Obj.tags):
        if getTagMagic(tag).getvalue() != magic.getvalue():
            continue

        matches.append(i)

    return matches


def getTagWithMagic(img3Obj: img3, magic: BytesIO) -> list[img3tag]:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    if not img3Obj.tags:
        raise ValueError('There are no tags!')

    if not isinstance(magic, BytesIO):
        raise TypeError

    if magic.getvalue() not in TAGS:
        raise ValueError(f'Unknown tag magic: {magic}!')

    tagIndexes = tagExists(img3Obj, magic)
    tags = [] if not tagIndexes else [img3Obj.tags[i] for i in tagIndexes]

    return tags


def initKbag() -> kbag:
    return kbag(0, 0, BytesIO(), BytesIO())


def parseKBAGHead(kbagTag: img3tag) -> kbag:
    if not isinstance(kbagTag, img3tag):
        raise TypeError

    kbagHeadData = getBufferAtIndex(kbagTag.data, 0, 8)
    kbagHeadUnpacked = unpack('<2I', kbagHeadData.getvalue())

    kbagObj = initKbag()
    kbagObj.cryptState = kbagHeadUnpacked[0]
    kbagObj.aesType = kbagHeadUnpacked[1]

    return kbagObj


def parseKBAG(kbagTag: img3tag) -> kbag:
    if not isinstance(kbagTag, img3tag):
        raise TypeError

    kbagObj = parseKBAGHead(kbagTag)

    if not isinstance(kbagObj.cryptState, int):
        raise TypeError

    if not isinstance(kbagObj.aesType, int):
        raise TypeError

    if not isinstance(kbagObj.iv, BytesIO):
        raise TypeError

    if not isinstance(kbagObj.key, BytesIO):
        raise TypeError

    if kbagObj.cryptState not in (KBAG_CRYPT_STATE_PRODUCTION, KBAG_CRYPT_STATE_DEVELOPMENT):
        raise ValueError(f'Unknown cryptState: {kbagObj.cryptState}!')

    if kbagObj.aesType not in AES_SIZES:
        raise ValueError(f'Unknown AES: {kbagObj.aesType}!')

    kbagObj.iv.seek(0, SEEK_SET)
    kbagObj.iv.write(getBufferAtIndex(kbagTag.data, 8, 16).getvalue())
    kbagObj.iv.seek(0, SEEK_SET)

    kbagObj.key.seek(0, SEEK_SET)
    kbagObj.key.write(getBufferAtIndex(kbagTag.data, 24, AES_SIZES[kbagObj.aesType]).getvalue())
    kbagObj.key.seek(0, SEEK_SET)

    return kbagObj


def printKBAG(kbagTag: img3tag) -> None:
    if not isinstance(kbagTag, img3tag):
        raise TypeError

    kbagObj = parseKBAG(kbagTag)
    cryptState = None

    if kbagObj.cryptState == KBAG_CRYPT_STATE_PRODUCTION:
        cryptState = 'Production'

    elif kbagObj.cryptState == KBAG_CRYPT_STATE_DEVELOPMENT:
        cryptState = 'Development'

    else:
        raise ValueError(f'Unknown cryptState: {kbagObj.cryptState}')

    print(f'CryptState: {cryptState}')
    print(f'AES: {kbagObj.aesType}')
    print(f'IV: {hexlify(kbagObj.iv.getvalue()).decode()}')
    print(f'Key: {hexlify(kbagObj.key.getvalue()).decode()}')


def makeTag(magic: BytesIO, data: BytesIO) -> img3tag:
    if not isinstance(magic, BytesIO):
        raise TypeError

    if not isinstance(data, BytesIO):
        raise TypeError

    tagMagic = magic.getvalue()

    if tagMagic not in TAGS:
        raise ValueError(f'Unknown tag magic: {tagMagic.decode()}')

    dataSize = getSizeOfIOStream(data)

    paddedData = pad(4, data)
    paddedDataSize = getSizeOfIOStream(paddedData)
    paddingSize = paddedDataSize - dataSize

    tag = initTag()
    tag.magic.seek(0, SEEK_SET)
    tag.magic.write(magic.getvalue()[::-1])
    tag.magic.seek(0, SEEK_SET)

    tag.totalSize = TAG_HEAD_SIZE + paddedDataSize
    tag.dataSize = dataSize

    tag.data.seek(0, SEEK_SET)
    tag.data.write(getBufferAtIndex(paddedData, 0, dataSize).getvalue())
    tag.data.seek(0, SEEK_SET)

    if paddingSize >= 1:
        tag.padding.seek(0, SEEK_SET)
        tag.padding.write(getBufferAtIndex(paddedData, dataSize, paddingSize).getvalue())
        tag.padding.seek(0, SEEK_SET)

    return tag


def dataTagPaddingIsZeroed(tag: img3tag) -> bool:
    if not isinstance(tag, img3tag):
        raise TypeError

    if getTagMagic(tag).getvalue() != b'DATA':
        raise ValueError('Incorrect tag type!')

    padSize = getSizeOfIOStream(tag.padding)
    zeroedPadding = BytesIO(b'\x00' * padSize)
    return tag.padding.getvalue() == zeroedPadding.getvalue()


def img3Decrypt(dataTag: img3tag, aes: int, iv: BytesIO | None, key: BytesIO | None) -> tuple[img3tag, bool]:
    if not isinstance(dataTag, img3tag):
        raise TypeError

    if not isinstance(aes, int):
        raise TypeError

    if getTagMagic(dataTag).getvalue() != b'DATA':
        raise ValueError('Tag must be of type: DATA!')

    block1Size = dataTag.dataSize & ~0xF
    block2Size = dataTag.dataSize & 0xF

    block1Data = getBufferAtIndex(dataTag.data, 0, block1Size)
    block2Data = getBufferAtIndex(dataTag.data, block1Size, block2Size)

    decryptBuffer = block1Data
    paddingIsZeroed = dataTagPaddingIsZeroed(dataTag)

    if not paddingIsZeroed:
        decryptBuffer.seek(0, SEEK_END)
        decryptBuffer.write(block2Data.getvalue())
        decryptBuffer.write(dataTag.padding.getvalue())
        decryptBuffer.seek(0, SEEK_SET)

    if not isAligned(getSizeOfIOStream(decryptBuffer), 16):
        raise ValueError('Decrypt buffer is not 16 byte aligned!')

    if iv and key:
        decryptBuffer = doAES(False, aes, decryptBuffer, iv, key)

    if paddingIsZeroed:
        decryptBuffer.seek(0, SEEK_END)
        decryptBuffer.write(block2Data.getvalue())
        decryptBuffer.seek(0, SEEK_SET)
    else:
        decryptBuffer = getBufferAtIndex(decryptBuffer, 0, dataTag.dataSize)

    newDataTag = makeTag(BytesIO(b'DATA'), decryptBuffer)
    return newDataTag, paddingIsZeroed


def handleKernelData(dataTag: img3tag, kASLRSupported: bool = False) -> img3tag:
    COMPRESSED_DATA_MAGIC = BytesIO(b'comp')
    UNCOMPRESSED_DATA_MAGIC = BytesIO(b'\xfe\xed\xfa\xce'[::-1])

    buffer = getBufferAtIndex(dataTag.data, 0, 4)
    mode = None

    if buffer.getvalue() == COMPRESSED_DATA_MAGIC.getvalue():
        mode = 'decompress'

    elif buffer.getvalue() == UNCOMPRESSED_DATA_MAGIC.getvalue():
        mode = 'compress'

    else:
        raise ValueError('Unable to determine mode!')

    if not isinstance(mode, str):
        raise TypeError

    if mode not in ('compress', 'decompress'):
        raise ValueError(f'Unknown mode: {mode}')

    newData = None

    if mode == 'compress':
        newData = compress(dataTag.data, kASLRSupported)
    else:
        newData = decompress(dataTag.data)

    newDataTag = makeTag(BytesIO(b'DATA'), newData)
    return newDataTag


def img3Encrypt(dataTag: img3tag, aes: int, iv: BytesIO | None, key: BytesIO | None, paddingWasZeroed: bool = False) -> img3tag:
    if not isinstance(dataTag, img3tag):
        raise TypeError

    if not isinstance(aes, int):
        raise TypeError

    if not isinstance(paddingWasZeroed, bool):
        raise TypeError

    if getTagMagic(dataTag).getvalue() != b'DATA':
        raise ValueError('Tag must be of type: DATA!')

    block1Size = dataTag.dataSize & ~0xF
    block2Size = dataTag.dataSize & 0xF
    block1Data = getBufferAtIndex(dataTag.data, 0, block1Size)
    block2Data = getBufferAtIndex(dataTag.data, block1Size, block2Size)
    encryptBuffer = block1Data

    if not paddingWasZeroed:
        encryptBuffer.seek(0, SEEK_END)
        encryptBuffer.write(block2Data.getvalue())
        encryptBuffer.write(dataTag.padding.getvalue())

    if not isAligned(getSizeOfIOStream(encryptBuffer), 16):
        raise ValueError('Encrypt buffer is not 16 byte aligned!')

    if iv and key:
        encryptBuffer = doAES(True, aes, encryptBuffer, iv, key)

    padding = BytesIO()
    encryptBufferSize = getSizeOfIOStream(encryptBuffer)

    if paddingWasZeroed:
        encryptBuffer.seek(0, SEEK_END)
        encryptBuffer.write(block2Data.getvalue())
    else:
        paddingSize = getSizeOfIOStream(dataTag.padding)

        if paddingSize >= 1:
            padding.write(getBufferAtIndex(encryptBuffer, encryptBufferSize - paddingSize, paddingSize).getvalue())
            encryptBuffer = getBufferAtIndex(encryptBuffer, 0, encryptBufferSize - paddingSize)

    newDataTag = makeTag(BytesIO(b'DATA'), encryptBuffer)

    if getSizeOfIOStream(padding) >= 1:
        if getSizeOfIOStream(newDataTag.padding) != getSizeOfIOStream(padding):
            raise ValueError(f'Expected padding size {getSizeOfIOStream(newDataTag.padding)}, got {getSizeOfIOStream(padding)}!')

        newDataTag.padding = padding

    return newDataTag


def updateImg3Head(img3Obj: img3) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError

    i = 0
    sigCheckArea = 0

    for tag in img3Obj.tags:
        i += tag.totalSize

        if getTagMagic(tag).getvalue() in (b'SHSH', b'CERT'):
            continue

        sigCheckArea += tag.totalSize

    img3Obj.fullSize = i + IMG3_HEAD_SIZE
    img3Obj.sizeNoPack = i
    img3Obj.sigCheckArea = sigCheckArea

    return img3Obj


def replaceTagInImg3Obj(img3Obj: img3, newTag: img3tag) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(newTag, img3tag):
        raise TypeError

    tags = img3Obj.tags.copy()

    for i, tag in enumerate(img3Obj.tags):
        if getTagMagic(tag).getvalue() != getTagMagic(newTag).getvalue():
            continue

        tags[i] = newTag
        break

    img3Obj.tags = tags
    return updateImg3Head(img3Obj)


def img3ToBytesIO(img3Obj: img3) -> BytesIO:
    if not isinstance(img3Obj, img3):
        raise TypeError

    img3HeadData = BytesIO(pack('<4s3I4s',
        img3Obj.magic.getvalue(),
        img3Obj.fullSize,
        img3Obj.sizeNoPack, 
        img3Obj.sigCheckArea, 
        img3Obj.ident.getvalue()
    ))

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    if not img3Obj.tags:
        raise ValueError('img3 does not have any tags!')

    tagsData = BytesIO()

    for tag in img3Obj.tags:
        tagHeadData = BytesIO(pack('<4s2I', tag.magic.getvalue(), tag.totalSize, tag.dataSize))
        tagHeadData.seek(0, SEEK_END)
        tagHeadData.write(tag.data.getvalue())
        tagHeadData.write(tag.padding.getvalue())

        tagsData.seek(0, SEEK_END)
        tagsData.write(tagHeadData.getvalue())

    img3Data = BytesIO()
    img3Data.write(img3HeadData.getvalue())
    img3Data.write(tagsData.getvalue())

    if getSizeOfIOStream(img3Data) != img3Obj.fullSize:
        raise ValueError(f'Img3 buffer is not of size: {img3Obj.fullSize}!')

    return img3Data


def findDifferencesBetweenTwoImg3s(img3Obj1: img3, img3Obj2: img3):
    if not isinstance(img3Obj1, img3):
        raise TypeError

    if not isinstance(img3Obj2, img3):
        raise TypeError

    if img3Obj1.magic != img3Obj2.magic:
        print(f'Magic: {img3Obj1.magic}, {img3Obj2.magic}')

    if img3Obj1.fullSize != img3Obj2.fullSize:
        print(f'Fullsize: {img3Obj1.fullSize}, {img3Obj2.fullSize}')

    if img3Obj1.sizeNoPack != img3Obj2.sizeNoPack:
        print(f'SizeNoPack: {img3Obj1.sizeNoPack}, {img3Obj2.sizeNoPack}')

    if img3Obj1.sigCheckArea != img3Obj2.sigCheckArea:
        print(f'SigCheckArea: {img3Obj1.sigCheckArea}, {img3Obj2.sigCheckArea}')

    if img3Obj1.ident != img3Obj2.ident:
        print(f'Ident: {img3Obj1.ident}, {img3Obj2.ident}')

    if not isinstance(img3Obj1.tags, list):
        raise TypeError

    if not img3Obj1.tags:
        raise ValueError('Img3 1 does not have any tags!')

    if not isinstance(img3Obj2.tags, list):
        raise TypeError

    if not img3Obj2.tags:
        raise ValueError('Img3 2 does not have any tags!')

    for tag1, tag2 in zip(img3Obj1.tags, img3Obj2.tags):
        if tag1.magic != tag2.magic:
            print(f'Magic: {tag1.magic}, {tag2.magic}')

        if tag1.totalSize != tag2.totalSize:
            print(f'Total size: {tag1.totalSize}, {tag2.totalSize}')

        if tag1.dataSize != tag2.dataSize:
            print(f'Data size: {tag1.dataSize}, {tag2.dataSize}')

        tag1PadSize = getSizeOfIOStream(tag1.padding)
        tag2PadSize = getSizeOfIOStream(tag2.padding)

        if tag1PadSize != tag2PadSize:
            print(f'Padding size: {tag1PadSize}, {tag2PadSize}')


def printImg3Info(img3Obj: img3) -> None:
    if not isinstance(img3Obj, img3):
        raise TypeError

    print(f'Magic: {getImg3Magic(img3Obj).getvalue().decode()}')
    print(f'Fullsize: {img3Obj.fullSize}')
    print(f'SizeNoPack: {img3Obj.sizeNoPack}')
    print(f'SigCheckArea: {img3Obj.sigCheckArea}')
    print(f'Ident: {getImg3Ident(img3Obj).getvalue().decode()}')

    if img3Obj.tags:
        if not isinstance(img3Obj.tags, list):
            raise TypeError

        for tag in img3Obj.tags:
            print(f'Magic: {getTagMagic(tag).getvalue().decode()}')
            print(f'Totalsize: {tag.totalSize}')
            print(f'Datasize: {tag.dataSize}')
            print(f'Padsize: {tag.totalSize-tag.dataSize-TAG_HEAD_SIZE}')


def getTagOffsetInImg3(img3Obj: img3, magic: bytes) -> int:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    if not img3Obj.tags:
        raise ValueError('No tags are present!')
    
    if magic not in TAGS:
        raise ValueError(f'Unknown magic: {magic}!')

    i = IMG3_HEAD_SIZE

    for tag in img3Obj.tags:
        if getTagMagic(tag).getvalue() == magic:
            break

        i += tag.totalSize

    if i not in range(img3Obj.fullSize + 1):
        raise ValueError(f'Bad index: {i}')

    return i


def verifySHSH(img3Obj: img3) -> bool | None:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    if not img3Obj.tags:
        raise ValueError('No tags are present!')

    shshTag = getTagWithMagic(img3Obj, BytesIO(b'SHSH'))

    if not shshTag:
        return

    shshTag = shshTag[0]

    if getSizeOfIOStream(shshTag.data) != 128:
        raise ValueError(f'SHSH data size mismatch. Got {getSizeOfIOStream(shshTag.data)}, expected 128!')

    certTag = getTagWithMagic(img3Obj, BytesIO(b'CERT'))

    if not certTag:
        return

    certTag = certTag[0]
    publicKey = extractPublicKeyFromDER(certTag.data)
    shshTagDataStart = getTagOffsetInImg3(img3Obj, b'SHSH')
    img3Data = img3ToBytesIO(img3Obj)
    img3SHA1Data = getBufferAtIndex(img3Data, TAG_HEAD_SIZE, shshTagDataStart)
    return doRSACheck(publicKey, shshTag.data, img3SHA1Data)


def getNestedImg3FromCERT(certTag: img3tag) -> img3 | None:
    if not isinstance(certTag, img3tag):
        raise TypeError

    if getTagMagic(certTag).getvalue() != b'CERT':
        raise ValueError('Incorrect img3tag type!')

    img3Data = extractNestedImages(certTag.data)

    if not isinstance(img3Data, bytes):
        raise TypeError

    if not img3Data:
        return

    try:
        img3Obj = readImg3(BytesIO(img3Data))
    except ValueError:
        return
    else:
        return img3Obj


def removeTagFromImg3(img3Obj: img3, magic: BytesIO, removeAll: bool = False) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not img3Obj.tags:
        return img3Obj

    if not isinstance(magic, BytesIO):
        raise TypeError

    if magic.getvalue() not in TAGS:
        raise ValueError(f'Unknown magic: {magic.getvalue()}!')

    if not isinstance(removeAll, bool):
        raise TypeError

    tagIndexes = tagExists(img3Obj, magic)

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
    return img3Obj


def make24KPWNLLB(img3Obj: img3, isN72: bool, isN88: bool) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError
    
    if not isinstance(img3Obj.tags, list):
        raise TypeError
    
    if not img3Obj.tags:
        raise ValueError('This image does not have any tags!')

    if not isinstance(isN72, bool):
        raise TypeError

    if not isinstance(isN88, bool):
        raise TypeError

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

    if isN88:
        typeTag = getTagWithMagic(img3Obj, BytesIO(b'TYPE'))

        if not typeTag:
            raise ValueError('This image does not contain a TYPE tag!')

        typeTag = typeTag[0]
        typeTag.padding = BytesIO(b'\x00' * getSizeOfIOStream(typeTag.padding))

        newImg3 = replaceTagInImg3Obj(img3Obj, typeTag)
    else:
        newImg3 = removeTagFromImg3(img3Obj, BytesIO(b'TYPE'), True)

    if not newImg3:
        raise ValueError('New Img3 is empty!')

    dataTag = getTagWithMagic(newImg3, BytesIO(b'DATA'))

    if not dataTag:
        raise ValueError('This image does not contain a DATA tag!')

    dataTag = dataTag[0]
    dataTagDword = getBufferAtIndex(dataTag.data, 0, 4).getvalue()
    dataTag.data = BytesIO(dword + getBufferAtIndex(dataTag.data, 4, dataTag.dataSize - 4).getvalue())

    newImg3 = removeTagFromImg3(newImg3, BytesIO(b'KBAG'), True)

    certTag = getTagWithMagic(newImg3, BytesIO(b'CERT'))

    if not certTag:
        raise ValueError('This image does not contain a CERT tag!')

    certTag = certTag[0]
    certTagData = BytesIO(certTag.data.getvalue() + certTag.padding.getvalue())
    certTagDataStartPos = getTagOffsetInImg3(img3Obj, b'CERT') + TAG_HEAD_SIZE
    sizeToFill = kpwnSize - certTagDataStartPos
    certTagDataPadded = pad(sizeToFill, certTagData)

    if isN72:
        shellcode = shellcode.replace(b'\xdf\xdb\x64\x80', dataTagDword)

    if isN88:
        shellcode = shellcode.replace(b'\xAA\xBB\xCC\xDD', dataTagDword)

    shellcodeSize = len(shellcode)
    shellcodeStart = shellcodeOffset - certTagDataStartPos
    certTagDataPadded = replaceBufferAtIndex(certTagDataPadded, BytesIO(shellcode), shellcodeStart, shellcodeSize)

    bootstrapSize = len(bootstrap)
    bootstrapStart = bootstrapOffset - certTagDataStartPos
    certTagDataPadded = replaceBufferAtIndex(certTagDataPadded, BytesIO(bootstrap), bootstrapStart, bootstrapSize)

    newCertTag = makeTag(BytesIO(b'CERT'), certTagDataPadded)
    newImg3 = replaceTagInImg3Obj(newImg3, newCertTag)

    if img3Obj.fullSize != kpwnSize:
        raise ValueError(f'LLB is not of size: {kpwnSize}!')

    return newImg3
