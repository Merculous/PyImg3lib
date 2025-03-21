
from binascii import hexlify
from struct import pack, unpack

from .der import extractNestedImages, extractPublicKeyFromDER
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
    b'diag' # 'cert' != 'CERT'
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

def readTag(data: bytes) -> img3tag:
    tag = img3tag(*unpack('<4s2I', data[:TAG_HEAD_SIZE]), data=None, padding=None)

    if not isinstance(tag.magic, bytes):
        raise TypeError

    if not isinstance(tag.totalSize, int):
        raise TypeError

    if not isinstance(tag.dataSize, int):
        raise TypeError

    if tag.magic[::-1] not in TAGS:
        raise ValueError(f'Unknown tag magic: {tag.magic[::-1]}')

    tag.data = data[TAG_HEAD_SIZE:TAG_HEAD_SIZE+tag.dataSize]

    paddingSize = tag.totalSize - tag.dataSize - TAG_HEAD_SIZE
    tag.padding = data[TAG_HEAD_SIZE+tag.dataSize:TAG_HEAD_SIZE+tag.dataSize+paddingSize]

    return tag


def readImg3(data: bytes) -> img3:
    dataSize = len(data)
    img3Obj = img3(*unpack('<4s3I4s', data[:IMG3_HEAD_SIZE]), tags=None)

    if not isinstance(img3Obj.magic, bytes):
        raise TypeError

    if not isinstance(img3Obj.fullSize, int):
        raise TypeError

    if not isinstance(img3Obj.sizeNoPack, int):
        raise TypeError

    if not isinstance(img3Obj.sigCheckArea, int):
        raise TypeError

    if not isinstance(img3Obj.ident, bytes):
        raise TypeError

    if img3Obj.magic[::-1] != IMG3_MAGIC:
        raise ValueError('This is not an Img3 file!')

    if img3Obj.fullSize != dataSize:
        raise ValueError(f'Size mismatch. Expected {dataSize}, got {img3Obj.fullSize}')

    if img3Obj.sizeNoPack != dataSize - IMG3_HEAD_SIZE:
        raise ValueError(f'Size mismatch. Expected {dataSize-IMG3_HEAD_SIZE}, got {img3Obj.sizeNoPack}')

    if img3Obj.ident[::-1] not in TYPES:
        raise ValueError(f'{img3Obj.ident} is not a valid type!')

    img3Obj.tags = []
    i = IMG3_HEAD_SIZE

    while i in range(img3Obj.fullSize):
        tagData = data[i:]
        tag = readTag(tagData)

        if not isinstance(tag, img3tag):
            raise TypeError

        img3Obj.tags.append(tag)
        i += tag.totalSize

    if i != img3Obj.fullSize:
        raise ValueError(f'Index error. Expected {img3Obj.fullSize}, got {i}!')

    return img3Obj


def getTagMagic(tag: img3tag) -> bytes:
    if not isinstance(tag, img3tag):
        raise TypeError

    if not isinstance(tag.magic, bytes):
        raise TypeError

    if not tag.magic:
        raise TypeError('Tag magic is empty!')

    return tag.magic[::-1]


def tagExists(img3Obj: img3, magic: bytes) -> list[int]:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(magic, bytes):
        raise TypeError

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    matches = []

    if not img3Obj.tags:
        return matches

    for i, tag in enumerate(img3Obj.tags):
        if getTagMagic(tag) != magic:
            continue

        matches.append(i)

    return matches


def getTagWithMagic(img3Obj: img3, magic: bytes) -> list[img3tag]:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    if not img3Obj.tags:
        raise ValueError('There are no tags!')

    if not isinstance(magic, bytes):
        raise TypeError

    if magic not in TAGS:
        raise ValueError(f'Unknown tag magic: {magic}!')

    tagIndexes = tagExists(img3Obj, magic)
    tags = [] if not tagIndexes else [img3Obj.tags[i] for i in tagIndexes]

    return tags


def parseKBAG(kbagTag: img3tag) -> kbag:
    if getTagMagic(kbagTag) != b'KBAG':
        raise ValueError('This tag is not a KBAG!')

    kbagObj = kbag(*unpack('<2I', kbagTag.data[:8]), iv=None, key=None)

    if kbagObj.cryptState not in (KBAG_CRYPT_STATE_PRODUCTION, KBAG_CRYPT_STATE_DEVELOPMENT):
        raise ValueError(f'Unknown crypt state: {kbagObj.cryptState}!')

    if kbagObj.aesType not in AES_SIZES:
        raise ValueError(f'Unknown AES: {kbagObj.aesType}!')

    kbagObj.iv = kbagTag.data[8:8+16]
    kbagObj.key = kbagTag.data[8+16:8+16+AES_SIZES[kbagObj.aesType]]

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
    print(f'IV: {hexlify(kbagObj.iv).decode()}')
    print(f'Key: {hexlify(kbagObj.key).decode()}')


def makeTag(magic: bytes, data: bytes) -> img3tag:
    if not isinstance(magic, bytes):
        raise TypeError

    if not isinstance(data, bytes):
        raise TypeError

    if magic not in TAGS:
        raise ValueError(f'Unknown tag magic: {magic}')

    dataSize = len(data)

    paddedData = pad(4, data)
    paddedDataSize = len(paddedData)
    paddingSize = paddedDataSize - dataSize

    totalSize = paddedDataSize + TAG_HEAD_SIZE

    tag = img3tag(magic[::-1], totalSize, dataSize, data=None, padding=None)
    tag.data = paddedData[:dataSize]
    tag.padding = paddedData[dataSize:dataSize+paddingSize]

    return tag


def dataTagPaddingIsZeroed(tag: img3tag) -> bool:
    if not isinstance(tag, img3tag):
        raise TypeError

    if getTagMagic(tag) != b'DATA':
        raise ValueError('Incorret tag type!')

    padSize = len(tag.padding)
    zeroedPadding = b'\x00' * padSize
    return tag.padding == zeroedPadding


def img3Decrypt(dataTag: img3tag, aes: int, iv: bytes | str | None, key: bytes | str | None) -> tuple[img3tag, bool]:
    if not isinstance(dataTag, img3tag):
        raise TypeError

    if getTagMagic(dataTag) != b'DATA':
        raise ValueError('Tag must be of type: DATA!')

    if isinstance(iv, str):
        iv = b''.fromhex(iv)

    if isinstance(key, str):
        key = b''.fromhex(key)

    block1Size = dataTag.dataSize & ~0xF
    block2Size = dataTag.dataSize & 0xF
    block1Data = dataTag.data[:block1Size]
    block2Data = dataTag.data[block1Size:block1Size+block2Size]
    decryptBuffer = block1Data

    paddingIsZeroed = dataTagPaddingIsZeroed(dataTag)

    if not paddingIsZeroed:
        decryptBuffer += block2Data + dataTag.padding

    if not isAligned(len(decryptBuffer), 16):
        raise ValueError('Decrypt buffer is not 16 byte aligned!')

    if iv and key:
        decryptBuffer = doAES(False, aes, decryptBuffer, iv, key)

    if paddingIsZeroed:
        decryptBuffer += block2Data
    else:
        decryptBuffer = decryptBuffer[:-len(dataTag.padding)]

    newDataTag = makeTag(b'DATA', decryptBuffer)
    return newDataTag, paddingIsZeroed


def handleKernelData(dataTag: img3tag, kASLRSupported: bool = False) -> img3tag:
    COMPRESSED_DATA_MAGIC = b'comp'
    UNCOMPRESSED_DATA_MAGIC = b'\xfe\xed\xfa\xce'[::-1]

    buffer = dataTag.data[:4]
    mode = None

    if buffer == COMPRESSED_DATA_MAGIC:
        mode = 'decompress'

    elif buffer == UNCOMPRESSED_DATA_MAGIC:
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

    newDataTag = makeTag(b'DATA', newData)
    return newDataTag


def img3Encrypt(dataTag: img3tag, aes: int, iv: bytes | str | None, key: bytes | str | None, paddingWasZeroed: bool = False) -> img3tag:
    if not isinstance(dataTag, img3tag):
        raise TypeError

    if getTagMagic(dataTag) != b'DATA':
        raise ValueError('Tag must be of type: DATA!')

    if isinstance(iv, str):
        iv = b''.fromhex(iv)

    if isinstance(key, str):
        key = b''.fromhex(key)

    block1Size = dataTag.dataSize & ~0xF
    block2Size = dataTag.dataSize & 0xF
    block1Data = dataTag.data[:block1Size]
    block2Data = dataTag.data[block1Size:block1Size+block2Size]
    encryptBuffer = block1Data

    if not paddingWasZeroed:
        encryptBuffer += block2Data + dataTag.padding

    if not isAligned(len(encryptBuffer), 16):
        raise ValueError('Encrypt buffer is not 16 byte aligned!')

    if iv and key:
        encryptBuffer = doAES(True, aes, encryptBuffer, iv, key)

    padding = None

    if paddingWasZeroed:
        encryptBuffer += block2Data
    else:
        if len(dataTag.padding) >= 1:
            padding = encryptBuffer[-len(dataTag.padding):]
            encryptBuffer = encryptBuffer[:-len(dataTag.padding)]

    newDataTag = makeTag(b'DATA', encryptBuffer)

    if padding:
        if len(newDataTag.padding) != len(padding):
            raise ValueError(f'Expected padding size {len(newDataTag.padding)}, got {len(padding)}!')

        newDataTag.padding = padding

    return newDataTag


def updateImg3Head(img3Obj: img3) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError

    i = 0
    sigCheckArea = 0

    for tag in img3Obj.tags:
        i += tag.totalSize

        if getTagMagic(tag) in (b'SHSH', b'CERT'):
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
        if getTagMagic(tag) != getTagMagic(newTag):
            continue

        tags[i] = newTag
        break

    img3Obj.tags = tags
    return updateImg3Head(img3Obj)


def img3ToBytes(img3Obj: img3) -> bytes:
    if not isinstance(img3Obj, img3):
        raise TypeError

    img3HeadData = pack('<4s3I4s',
        img3Obj.magic,
        img3Obj.fullSize,
        img3Obj.sizeNoPack, 
        img3Obj.sigCheckArea, 
        img3Obj.ident
    )

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    if not img3Obj.tags:
        raise ValueError('img3 does not have any tags!')

    tagsData = b''

    for tag in img3Obj.tags:
        tagHeadData = pack('<4s2I', tag.magic, tag.totalSize, tag.dataSize)
        tagData = tagHeadData + tag.data + tag.padding
        tagsData += tagData

    img3Data = img3HeadData + tagsData

    if len(img3Data) != img3Obj.fullSize:
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

        tag1PadSize = len(tag1.padding)
        tag2PadSize = len(tag2.padding)

        if tag1PadSize != tag2PadSize:
            print(f'Padding size: {tag1PadSize}, {tag2PadSize}')


def printImg3Info(img3Obj: img3) -> None:
    if not isinstance(img3Obj, img3):
        raise TypeError

    if not isinstance(img3Obj.tags, list):
        raise TypeError

    print(f'Magic: {img3Obj.magic[::-1].decode()}')
    print(f'Fullsize: {img3Obj.fullSize}')
    print(f'SizeNoPack: {img3Obj.sizeNoPack}')
    print(f'SigCheckArea: {img3Obj.sigCheckArea}')
    print(f'Ident: {img3Obj.ident[::-1].decode()}')

    if img3Obj.tags:
        for tag in img3Obj.tags:
            print(f'Magic: {tag.magic[::-1].decode()}')
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
        if getTagMagic(tag) == magic:
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

    shshTag = getTagWithMagic(img3Obj, b'SHSH')

    if not shshTag:
        return

    shshTag = shshTag[0]

    if len(shshTag.data) != 128:
        raise ValueError(f'SHSH data size mismatch. Got {len(shshTag.data)}, expected 128!')

    certTag = getTagWithMagic(img3Obj, b'CERT')

    if not certTag:
        return

    certTag = certTag[0]
    publicKey = extractPublicKeyFromDER(certTag.data)
    shshTagDataStart = getTagOffsetInImg3(img3Obj, b'SHSH')
    img3SHA1Data = img3ToBytes(img3Obj)[TAG_HEAD_SIZE:shshTagDataStart]
    return doRSACheck(publicKey, shshTag.data, img3SHA1Data)


def getNestedImg3FromCERT(certTag: img3tag) -> img3 | None:
    if not isinstance(certTag, img3tag):
        raise TypeError

    if getTagMagic(certTag) != b'CERT':
        raise ValueError('Incorrect img3tag type!')

    img3Data = extractNestedImages(certTag.data)

    if not isinstance(img3Data, bytes):
        raise TypeError

    if not img3Data:
        return

    return readImg3(img3Data)
