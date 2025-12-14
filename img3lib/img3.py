
from binascii import hexlify
from itertools import zip_longest
from struct import pack, unpack

from binpatch.utils import getBufferAtIndex, replaceBufferAtIndex
from Crypto.Hash import SHA1

from .crypto import AES_SIZES, doAES, doRSACheck
from .der import (decodeDER, extractNestedImages, extractPublicKeyFromDER,
                  extractSHA1HashesFromAPTicket)
from .kpwn import (KPWN_BOOTSTRAP_OFFSET, KPWN_SHELLCODE_OFFSET,
                   N72_24KPWN_SIZE, N72_BOOTSTRAP, N72_SHELLCODE,
                   N72_SHELLCODE_ADDRESS, N72_SHELLCODE_DWORD_INDEX,
                   N88_24KPWN_SIZE, N88_BOOTSTRAP, N88_SHELLCODE,
                   N88_SHELLCODE_ADDRESS, N88_SHELLCODE_DWORD_INDEX)
from .lzsscode import compress, decompress
from .types import img3, img3tag, kbag
from .utils import isAligned, pad

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


def initTag() -> img3tag:
    return img3tag(b'', 0, 0, b'', b'')


def initImg3() -> img3:
    return img3(b'', 0, 0, 0, b'', [])


def readTagHead(data: bytes) -> img3tag:
    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    if not data:
        raise ValueError('No data to read!')

    if len(data) < TAG_HEAD_SIZE:
        raise ValueError('Not enough data to read!')

    tagHeadData = getBufferAtIndex(data, 0, TAG_HEAD_SIZE)
    magic, totalSize, dataSize = unpack('<4s2I', tagHeadData)

    tag = initTag()
    tag.magic = magic
    tag.totalSize = totalSize
    tag.dataSize = dataSize

    return tag


def getTagMagic(tag: img3tag) -> bytes:
    if not isinstance(tag, img3tag):
        raise TypeError(f'Tag must be of type: {img3tag}')

    if not isinstance(tag.magic, bytes):
        raise TypeError(f'Magic must be of type: {bytes}')

    if len(tag.magic) != 4:
        raise ValueError('Magic must be 4 bytes!')

    magic = tag.magic[::-1]
    return magic


def getTagTotalSize(tag: img3tag) -> int:
    if not isinstance(tag, img3tag):
        raise TypeError(f'Tag must be of type: {img3tag}')

    if not isinstance(tag.totalSize, int):
        raise TypeError(f'totalSize must be of type: {int}')

    return tag.totalSize


def getTagDataSize(tag: img3tag) -> int:
    if not isinstance(tag, img3tag):
        raise TypeError(f'Tag must be of type: {img3tag}')

    if not isinstance(tag.dataSize, int):
        raise TypeError(f'dataSize must be of type: {int}')

    return tag.dataSize


def getTagPadSize(tag: img3tag) -> int:
    if not isinstance(tag, img3tag):
        raise TypeError(f'Tag must be of type: {img3tag}')

    if not isinstance(tag.totalSize, int):
        raise TypeError(f'totalSize must be of type: {int}')

    if not isinstance(tag.dataSize, int):
        raise TypeError(f'dataSize must be of type: {int}')

    padSize = tag.totalSize - tag.dataSize - TAG_HEAD_SIZE
    return padSize


def readTag(data: bytes) -> img3tag:
    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    dataSize = len(data)

    if not data:
        raise ValueError('No data to read!')

    if dataSize < TAG_HEAD_SIZE:
        raise ValueError('Not enough data to read!')

    tag = readTagHead(data)

    if not isinstance(tag.magic, bytes):
        raise TypeError(f'Magic must be of type: {bytes}')

    if not isinstance(tag.totalSize, int):
        raise TypeError(f'totalSize must be of type: {int}')

    if not isinstance(tag.dataSize, int):
        raise TypeError(f'dataSize must be of type: {int}')

    if not isinstance(tag.data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    if not isinstance(tag.padding, bytes):
        raise TypeError(f'Padding must be of type: {bytes}')

    tagMagic = getTagMagic(tag)

    if tagMagic not in TAGS:
        raise ValueError(f'Unknown tag magic: {tagMagic}')

    tag.data = getBufferAtIndex(data, TAG_HEAD_SIZE, tag.dataSize)

    paddingSize = getTagPadSize(tag)

    if paddingSize >= 1:
        tag.padding = getBufferAtIndex(data, TAG_HEAD_SIZE + tag.dataSize, paddingSize)

    return tag


def getTagData(tag: img3tag) -> bytes:
    if not isinstance(tag, img3tag):
        raise TypeError(f'Tag must be of type: {img3tag}')

    if not isinstance(tag.data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    return tag.data


def getTagPadding(tag: img3tag) -> bytes:
    if not isinstance(tag, img3tag):
        raise TypeError(f'Tag must be of type: {img3tag}')

    if not isinstance(tag.padding, bytes):
        raise TypeError(f'Padding must be of type: {bytes}')

    return tag.padding


def readImg3Head(data: bytes) -> img3:
    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    dataSize = len(data)

    if not data:
        raise ValueError('No data to read!')

    if dataSize < IMG3_HEAD_SIZE:
        raise ValueError('Not enough data to read!')
    
    img3HeadData = getBufferAtIndex(data, 0, IMG3_HEAD_SIZE)
    magic, fullSize, sizeNoPack, sigCheckArea, ident = unpack('<4s3I4s', img3HeadData)

    img3Obj = initImg3()
    img3Obj.magic = magic
    img3Obj.fullSize = fullSize
    img3Obj.sizeNoPack = sizeNoPack
    img3Obj.sigCheckArea = sigCheckArea
    img3Obj.ident = ident

    return img3Obj


def getImg3Magic(img3Obj: img3) -> bytes:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(img3Obj.magic, bytes):
        raise TypeError(f'Magic must be of type: {bytes}')

    if len(img3Obj.magic) != 4:
        raise ValueError('Magic must be 4 bytes!')

    magic = img3Obj.magic[::-1]
    return magic


def getImg3FullSize(img3Obj: img3) -> int:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(img3Obj.fullSize, int):
        raise TypeError(f'fullSize must be of type: {int}')

    return img3Obj.fullSize


def getImg3SizeNoPack(img3Obj: img3) -> int:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(img3Obj.sizeNoPack, int):
        raise TypeError(f'sizeNoPack must be of type: {int}')

    return img3Obj.sizeNoPack


def getImg3SigCheckArea(img3Obj: img3) -> int:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(img3Obj.sigCheckArea, int):
        raise TypeError(f'sigCheckArea must be of type: {int}')

    return img3Obj.sigCheckArea


def getImg3Ident(img3Obj: img3) -> bytes:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(img3Obj.ident, bytes):
        raise TypeError(f'Ident must be of type: {bytes}')

    if len(img3Obj.ident) != 4:
        raise ValueError('Ident must be 4 bytes!')

    ident = img3Obj.ident[::-1]
    return ident


def readImg3(data: bytes) -> img3:
    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    if not data:
        raise ValueError('No data to read!')

    dataSize = len(data)

    if dataSize < IMG3_HEAD_SIZE:
        raise ValueError('Not enough data to read!')

    img3Obj = readImg3Head(data)

    if not isinstance(img3Obj.magic, bytes):
        raise TypeError(f'Magic must be of type: {bytes}')

    if not isinstance(img3Obj.fullSize, int):
        raise TypeError(f'fullSize must be of type: {int}')

    if not isinstance(img3Obj.sizeNoPack, int):
        raise TypeError(f'sizeNoPack must be of type: {int}')

    if not isinstance(img3Obj.sigCheckArea, int):
        raise TypeError(f'sigCheckArea must be of type: {int}')

    if not isinstance(img3Obj.ident, bytes):
        raise TypeError(f'Ident must be of type: {bytes}')

    if getImg3Magic(img3Obj) != IMG3_MAGIC:
        raise ValueError('This is not an Img3 file!')

    if getImg3FullSize(img3Obj) != dataSize:
        raise ValueError(f'Size mismatch. Expected {dataSize}, got {getImg3FullSize(img3Obj)}')

    if getImg3SizeNoPack(img3Obj) != dataSize - IMG3_HEAD_SIZE:
        raise ValueError(f'Size mismatch. Expected {dataSize-IMG3_HEAD_SIZE}, got {getImg3SizeNoPack(img3Obj)}')

    if getImg3Ident(img3Obj) not in TYPES:
        raise ValueError(f'{getImg3Ident(img3Obj)} is not a valid type!')

    i = IMG3_HEAD_SIZE

    while i in range(getImg3FullSize(img3Obj)):
        tagData = getBufferAtIndex(data, i, getImg3FullSize(img3Obj) - i)
        tag = readTag(tagData)

        if not isinstance(tag, img3tag):
            raise TypeError(f'Tag must be of type: {img3tag}')

        img3Obj.tags.append(tag)
        i += getTagTotalSize(tag)

    if i != getImg3FullSize(img3Obj):
        raise ValueError(f'Index error. Expected {getImg3FullSize(img3Obj)}, got {i}!')

    return img3Obj


def tagExists(img3Obj: img3, magic: bytes) -> list[int]:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(magic, bytes):
        raise TypeError(f'Magic must be of type: {bytes}')

    if not isinstance(img3Obj.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

    if len(magic) != 4:
        raise ValueError('Magic must be 4 bytes!')

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
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(img3Obj.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

    if not img3Obj.tags:
        raise ValueError('There are no tags!')

    if not isinstance(magic, bytes):
        raise TypeError

    if len(magic) != 4:
        raise ValueError('Magic must be 4 bytes!')

    if magic not in TAGS:
        raise ValueError(f'Unknown tag magic: {magic}!')

    tagIndexes = tagExists(img3Obj, magic)
    tags = [] if not tagIndexes else [img3Obj.tags[i] for i in tagIndexes]

    return tags


def initKbag() -> kbag:
    return kbag(0, 0, b'', b'')


def parseKBAGHead(kbagTag: img3tag) -> kbag:
    if not isinstance(kbagTag, img3tag):
        raise TypeError(f'kbagTag must be of type: {img3tag}')

    kbagHeadSize = 8
    kbagHeadData = getBufferAtIndex(kbagTag.data, 0, kbagHeadSize)
    cryptState, aesType = unpack('<2I', kbagHeadData)

    kbagObj = initKbag()
    kbagObj.cryptState = cryptState
    kbagObj.aesType = aesType

    return kbagObj


def parseKBAG(kbagTag: img3tag) -> kbag:
    if not isinstance(kbagTag, img3tag):
        raise TypeError(f'kbagTag must be of type: {img3tag}')

    kbagObj = parseKBAGHead(kbagTag)

    if not isinstance(kbagObj.cryptState, int):
        raise TypeError(f'cryptState must be of type: {int}')

    if not isinstance(kbagObj.aesType, int):
        raise TypeError(f'aesType must be of type: {int}')

    if not isinstance(kbagObj.iv, bytes):
        raise TypeError(f'IV must be of type: {bytes}')

    if not isinstance(kbagObj.key, bytes):
        raise TypeError(f'Key must be of type: {bytes}')

    if kbagObj.cryptState not in (KBAG_CRYPT_STATE_PRODUCTION, KBAG_CRYPT_STATE_DEVELOPMENT):
        raise ValueError(f'Unknown cryptState: {kbagObj.cryptState}!')

    if kbagObj.aesType not in AES_SIZES:
        raise ValueError(f'Unknown AES: {kbagObj.aesType}!')

    kbagHeadSize = 8
    ivSize = 16
    keySize = AES_SIZES[kbagObj.aesType]

    kbagObj.iv = getBufferAtIndex(kbagTag.data, kbagHeadSize, ivSize)
    kbagObj.key = getBufferAtIndex(kbagTag.data, kbagHeadSize + ivSize, keySize)

    return kbagObj


def printKBAG(kbagTag: img3tag) -> None:
    if not isinstance(kbagTag, img3tag):
        raise TypeError(f'kbagTag must be of type: {img3tag}')

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


def makeTag(magic: bytes, data: bytes | None) -> img3tag:
    if not isinstance(magic, bytes):
        raise TypeError(f'Magic must be of type: {bytes}')

    if not isinstance(data, bytes):
        raise TypeError(f'Data must be of type: {bytes}')

    if len(magic) != 4:
        raise ValueError('Magic must be 4 bytes!')

    if not data:
        raise ValueError('No data to read!')

    if magic not in TAGS:
        raise ValueError(f'Unknown tag magic: {magic.decode()}')

    dataSize = len(data)

    paddedData = pad(4, bytearray(data))
    paddedDataSize = len(paddedData)
    paddingSize = paddedDataSize - dataSize
    paddedData = bytes(paddedData)

    tag = initTag()
    tag.magic = magic[::-1]
    tag.totalSize = TAG_HEAD_SIZE + paddedDataSize
    tag.dataSize = dataSize
    tag.data = getBufferAtIndex(paddedData, 0, dataSize)

    if paddingSize >= 1:
        tag.padding = getBufferAtIndex(paddedData, dataSize, paddingSize)

    return tag


def dataTagPaddingIsZeroed(tag: img3tag) -> bool:
    if not isinstance(tag, img3tag):
        raise TypeError(f'Tag must be of type: {img3tag}')

    if getTagMagic(tag) != b'DATA':
        raise ValueError('Incorrect tag type!')

    padSize = len(tag.padding)
    zeroedPadding = b'\x00' * padSize
    return tag.padding == zeroedPadding


def img3Decrypt(dataTag: img3tag, aes: int, iv: bytes | None, key: bytes | None) -> tuple[img3tag, bool]:
    if not isinstance(dataTag, img3tag):
        raise TypeError(f'dataTag must be of type: {img3tag}')

    if not isinstance(aes, int):
        raise TypeError(f'AES must be of type: {int}')

    if getTagMagic(dataTag) != b'DATA':
        raise ValueError('Tag must be of type: DATA!')

    block1Size = dataTag.dataSize & ~0xF
    block2Size = dataTag.dataSize & 0xF

    block1Data = getBufferAtIndex(dataTag.data, 0, block1Size)
    block2Data = getBufferAtIndex(dataTag.data, block1Size, block2Size) if block2Size >= 1 else b''

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
        decryptBuffer = getBufferAtIndex(decryptBuffer, 0, dataTag.dataSize)

    newDataTag = makeTag(b'DATA', decryptBuffer)
    return newDataTag, paddingIsZeroed


def handleKernelData(dataTag: img3tag, kASLRSupported: bool = False) -> img3tag:
    if not isinstance(dataTag, img3tag):
        raise TypeError(f'dataTag must be of type: {img3tag}')

    if not isinstance(kASLRSupported, bool):
        raise TypeError(f'kASLRSupported must be of type: {bool}')

    COMPRESSED_DATA_MAGIC = b'comp'
    UNCOMPRESSED_DATA_MAGIC = b'\xfe\xed\xfa\xce'[::-1]

    buffer = getBufferAtIndex(dataTag.data, 0, 4)
    mode = None

    if buffer == COMPRESSED_DATA_MAGIC:
        mode = 'decompress'

    elif buffer == UNCOMPRESSED_DATA_MAGIC:
        mode = 'compress'

    else:
        raise ValueError('Unable to determine mode!')

    if not isinstance(mode, str):
        raise TypeError(f'Mode must be of type: {str}')

    if mode not in ('compress', 'decompress'):
        raise ValueError(f'Unknown mode: {mode}')

    newData = None

    if mode == 'compress':
        newData = compress(dataTag.data, kASLRSupported)
    else:
        newData = decompress(dataTag.data)

    newDataTag = makeTag(b'DATA', newData)
    return newDataTag


def img3Encrypt(dataTag: img3tag, aes: int, iv: bytes | None, key: bytes | None, paddingWasZeroed: bool = False) -> img3tag:
    if not isinstance(dataTag, img3tag):
        raise TypeError(f'dataTag must be of type: {img3tag}')

    if not isinstance(aes, int):
        raise TypeError(f'AES must be of type: {int}')

    if not isinstance(paddingWasZeroed, bool):
        raise TypeError(f'paddingWasZeroed must be of type: {bool}')

    if getTagMagic(dataTag) != b'DATA':
        raise ValueError('Tag must be of type: DATA!')

    block1Size = dataTag.dataSize & ~0xF
    block2Size = dataTag.dataSize & 0xF
    block1Data = getBufferAtIndex(dataTag.data, 0, block1Size)
    block2Data = getBufferAtIndex(dataTag.data, block1Size, block2Size) if block2Size >= 1 else b''
    encryptBuffer = block1Data

    if not paddingWasZeroed:
        encryptBuffer = block2Data + dataTag.padding

    # Ensure we pad the encrypt buffer
    encryptBuffer = pad(16, bytearray(encryptBuffer))

    if not isAligned(len(encryptBuffer), 16):
        raise ValueError('Encrypt buffer is not 16 byte aligned!')

    encryptBuffer = bytes(encryptBuffer)

    if iv and key:
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

    newDataTag = makeTag(b'DATA', encryptBuffer)

    if padding:
        if len(newDataTag.padding) != len(padding):
            raise ValueError(f'Expected padding size {len(newDataTag.padding)}, got {len(padding)}!')

        newDataTag.padding = padding

    return newDataTag


def updateImg3Head(img3Obj: img3) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

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
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(newTag, img3tag):
        raise TypeError(f'newTag must be of type: {img3tag}')

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
        raise TypeError(f'img3Obj must be of type: {img3}')

    img3HeadData = pack('<4s3I4s',
        img3Obj.magic,
        img3Obj.fullSize,
        img3Obj.sizeNoPack, 
        img3Obj.sigCheckArea, 
        img3Obj.ident
    )

    if not isinstance(img3Obj.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

    if not img3Obj.tags:
        raise ValueError('img3 does not have any tags!')

    tagsData = b''

    for tag in img3Obj.tags:
        tagsData += pack('<4s2I', tag.magic, tag.totalSize, tag.dataSize) + tag.data + tag.padding

    img3Data = img3HeadData + tagsData

    if len(img3Data) != img3Obj.fullSize:
        raise ValueError(f'Img3 buffer is not of size: {img3Obj.fullSize}!')

    return img3Data


def findDifferencesBetweenTwoImg3s(img3Obj1: img3, img3Obj2: img3):
    if not isinstance(img3Obj1, img3):
        raise TypeError(f'img3Obj1 must be of type: {img3}')

    if not isinstance(img3Obj2, img3):
        raise TypeError(f'img3Obj2 must be of type: {img3}')

    if getImg3Magic(img3Obj1) != getImg3Magic(img3Obj2):
        print(f'Magic: {getImg3Magic(img3Obj1)}, {getImg3Magic(img3Obj2)}')

    if getImg3FullSize(img3Obj1) != getImg3FullSize(img3Obj2):
        print(f'Fullsize: {getImg3FullSize(img3Obj1)}, {getImg3FullSize(img3Obj2)}')

    if getImg3SizeNoPack(img3Obj1) != getImg3SizeNoPack(img3Obj2):
        print(f'SizeNoPack: {getImg3SizeNoPack(img3Obj1)}, {getImg3SizeNoPack(img3Obj2)}')

    if getImg3SigCheckArea(img3Obj1) != getImg3SigCheckArea(img3Obj2):
        print(f'SigCheckArea: {getImg3SigCheckArea(img3Obj1)}, {getImg3SigCheckArea(img3Obj2)}')

    if getImg3Ident(img3Obj1) != getImg3Ident(img3Obj2):
        print(f'Ident: {getImg3Ident(img3Obj1)}, {getImg3Ident(img3Obj2)}')

    if not isinstance(img3Obj1.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

    if not img3Obj1.tags:
        raise ValueError('Img3 1 does not have any tags!')

    if not isinstance(img3Obj2.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

    if not img3Obj2.tags:
        raise ValueError('Img3 2 does not have any tags!')

    for tag1, tag2 in zip_longest(img3Obj1.tags, img3Obj2.tags):
        if tag1 and tag2:
            print(f'Magic: {getTagMagic(tag1)}, {getTagMagic(tag2)}')
    
            if getTagTotalSize(tag1) != getTagTotalSize(tag2):
                print(f'Total size: {getTagTotalSize(tag1)}, {getTagTotalSize(tag2)}')

            if getTagDataSize(tag1) != getTagDataSize(tag2):
                print(f'Data size: {getTagDataSize(tag1)}, {getTagDataSize(tag2)}')

            tag1PadSize = len(tag1.padding)
            tag2PadSize = len(tag2.padding)

            if tag1PadSize != tag2PadSize:
                print(f'Padding size: {tag1PadSize}, {tag2PadSize}')

        if tag1 and tag2 is None:
            print(f'Magic: {getTagMagic(tag1)}, {None}')
            print(f'Total size: {getTagTotalSize(tag1)}, {None}')
            print(f'Data size: {getTagDataSize(tag1)}, {None}')
            print(f'Padding size: {getTagPadSize(tag1)}, {None}')

        if tag1 is None and tag2:
            print(f'Magic: {None}, {getTagMagic(tag2)}')
            print(f'Total size: {None}, {getTagTotalSize(tag2)}')
            print(f'Data size: {None}, {getTagDataSize(tag2)}')
            print(f'Padding size: {None}, {getTagPadSize(tag2)}')


def printImg3Info(img3Obj: img3) -> None:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    print(f'Magic: {getImg3Magic(img3Obj).decode()}')
    print(f'Fullsize: {getImg3FullSize(img3Obj)}')
    print(f'SizeNoPack: {getImg3SizeNoPack(img3Obj)}')
    print(f'SigCheckArea: {getImg3SigCheckArea(img3Obj)}')
    print(f'Ident: {getImg3Ident(img3Obj).decode()}')

    if img3Obj.tags:
        if not isinstance(img3Obj.tags, list):
            raise TypeError(f'Tags must be of type: {list}')

        for tag in img3Obj.tags:
            print(f'Magic: {getTagMagic(tag).decode()}')
            print(f'Totalsize: {getTagTotalSize(tag)}')
            print(f'Datasize: {getTagDataSize(tag)}')
            print(f'Padsize: {getTagPadSize(tag)}')


def getTagOffsetInImg3(img3Obj: img3, magic: bytes) -> int:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(magic, bytes):
        raise TypeError(f'Magic must be of type: {bytes}')

    if not isinstance(img3Obj.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

    if not magic:
        raise ValueError('No data to read!')

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
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(img3Obj.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

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
    img3Data = img3ToBytes(img3Obj)
    img3SHA1Data = getBufferAtIndex(img3Data, 12, img3Obj.sigCheckArea + 8)
    return doRSACheck(publicKey, shshTag.data, img3SHA1Data)


def removeTagFromImg3(img3Obj: img3, magic: bytes, removeAll: bool = False) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not img3Obj.tags:
        return img3Obj

    if not isinstance(magic, bytes):
        raise TypeError(f'Magic must be of type: {bytes}')

    if len(magic) != 4:
        raise ValueError('Magic must be 4 bytes!')

    if magic not in TAGS:
        raise ValueError(f'Unknown magic: {magic}!')

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
    return updateImg3Head(img3Obj)


def make24KPWNLLB(img3Obj: img3, isN72: bool, isN88: bool) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')
    
    if not isinstance(img3Obj.tags, list):
        raise TypeError(f'Tags must be of type: {list}')
    
    if not img3Obj.tags:
        raise ValueError('This image does not have any tags!')

    if not isinstance(isN72, bool):
        raise TypeError(f'isN72 must be of type: {bool}')

    if not isinstance(isN88, bool):
        raise TypeError(f'isN88 must be of type: {bool}')

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

    if isN88:
        typeTag = getTagWithMagic(img3Obj, b'TYPE')

        if not typeTag:
            raise ValueError('This image does not contain a TYPE tag!')

        typeTag = typeTag[0]
        typeTag.padding = b'\x00' * len(typeTag.padding)

        newImg3 = replaceTagInImg3Obj(img3Obj, typeTag)
    else:
        newImg3 = removeTagFromImg3(img3Obj, b'TYPE', True)

    if not newImg3:
        raise ValueError('New Img3 is empty!')

    dataTag = getTagWithMagic(newImg3, b'DATA')

    if not dataTag:
        raise ValueError('This image does not contain a DATA tag!')

    dataTag = dataTag[0]
    dataTagDword = getBufferAtIndex(dataTag.data, 0, 4)
    dataTag.data = dword + getBufferAtIndex(dataTag.data, 4, dataTag.dataSize - 4)

    newImg3 = removeTagFromImg3(newImg3, b'KBAG', True)

    certTag = getTagWithMagic(newImg3, b'CERT')

    if not certTag:
        raise ValueError('This image does not contain a CERT tag!')

    certTag = certTag[0]
    certTagData = certTag.data + certTag.padding
    certTagDataStartPos = getTagOffsetInImg3(img3Obj, b'CERT') + TAG_HEAD_SIZE
    sizeToFill = kpwnSize - certTagDataStartPos
    certTagDataPadded = pad(sizeToFill, bytearray(certTagData))

    shellcode = replaceBufferAtIndex(bytearray(shellcode), dataTagDword, dwordIndex, 4)

    shellcodeSize = len(shellcode)
    shellcodeStart = shellcodeOffset - certTagDataStartPos
    certTagDataPadded = replaceBufferAtIndex(certTagDataPadded, bytes(shellcode), shellcodeStart, shellcodeSize)

    bootstrapSize = len(bootstrap)
    bootstrapStart = bootstrapOffset - certTagDataStartPos
    certTagDataPadded = replaceBufferAtIndex(certTagDataPadded, bootstrap, bootstrapStart, bootstrapSize)

    newCertTag = makeTag(b'CERT', bytes(certTagDataPadded))
    newImg3 = replaceTagInImg3Obj(newImg3, newCertTag)

    if img3Obj.fullSize != kpwnSize:
        raise ValueError(f'LLB is not of size: {kpwnSize}!')

    return newImg3


def insertTagInImg3(img3Obj: img3, tag: img3tag) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {img3}')

    if not isinstance(img3Obj.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

    if not img3Obj.tags:
        raise ValueError('No tags are present!')

    if not isinstance(tag, img3tag):
        raise TypeError

    img3Obj.tags.append(tag)
    return updateImg3Head(img3Obj)



def signImg3(img3Obj: img3, blobData: dict, manifestData: dict) -> img3:
    if not isinstance(img3Obj, img3):
        raise TypeError(f'img3Obj must be of type: {im3}')

    if not isinstance(img3Obj.tags, list):
        raise TypeError(f'Tags must be of type: {list}')

    if not img3Obj.tags:
        raise ValueError('No tags are present!')

    if not isinstance(blobData, dict):
        raise TypeError(f'blobData must be of type: {dict}')

    if not blobData:
        raise ValueError('Blob data is empty!')

    if not isinstance(manifestData, dict):
        raise TypeError(f'manifestData must be of type: {dict}')

    if not manifestData:
        raise ValueError('Manifest data is empty!')

    manifest = manifestData['BuildIdentities'][0]['Manifest']
    img3SHA1 = None
    imageName = None

    for name in manifest:
        sha1Digest = manifest[name].get('Digest')

        if sha1Digest is None:
            continue

        sha1Buffer = getBufferAtIndex(img3ToBytes(img3Obj), 12, img3Obj.sigCheckArea + 8)
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
        newImg3 = insertTagInImg3(newImg3, tag)

    return newImg3


def getNestedImageInCERT(certTag: img3tag) -> img3 | None:
    if not isinstance(certTag, img3tag):
        raise TypeError(f'Tag must be of type: {img3tag}')

    magic = getTagMagic(certTag)

    if magic != b'CERT':
        raise ValueError(f'Incorrect tag magic! Got {magic}!')

    if not certTag.data:
        raise ValueError('CERT data is empty!')

    derData = decodeDER(certTag.data)
    nestedData = extractNestedImages(derData)
    nestedImage = None

    try:
        nestedImage = readImg3(nestedData)
    except ValueError:
        return
    else:
        return nestedImage
