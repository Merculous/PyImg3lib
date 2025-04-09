
import json
import plistlib
import sys
from io import BytesIO
from pathlib import Path
from struct import unpack

from binpatch.io import getSizeOfIOStream
from binpatch.utils import getBufferAtIndex
from lykos.client import Client
from lykos.errors import PageNotFound

from img3lib.der import decodeDER
from img3lib.img3 import (BORDS, CHIPS, IMG3_HEAD_SIZE, SEPOS, TYPES,
                          getImg3FullSize, getImg3Ident, getImg3SigCheckArea,
                          getImg3SizeNoPack, getTagMagic, getTagWithMagic,
                          handleKernelData, img3Decrypt, img3Encrypt,
                          parseKBAG, readImg3, replaceTagInImg3Obj, verifySHSH)
from img3lib.types import img3
from img3lib.utils import isAligned


def getPaths(path: str) -> list[Path]:
    return [p for p in Path(path).rglob('*')]


def readRestorePlist(data: bytes) -> dict:
    plist = plistlib.loads(data)

    info = {
        plist['ProductVersion']: {
            'device': plist['ProductType'],
            'buildid': plist['ProductBuildVersion']
        }
    }

    return info


def getKeys(client: Client, device: str, buildid: str) -> dict | None:
    try:
        keyData = client.get_key_data(device, buildid)
    except PageNotFound:
        return
    except Exception:
        raise
    else:
        return keyData


def writeJSON(path, data) -> None:
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


class Img3Test:
    def __init__(self, img3: img3, version: str) -> None:
        self.img3 = img3
        self.version = version

    def test_TYPE(self) -> bool | None:
        typeTag = getTagWithMagic(self.img3, BytesIO(b'TYPE'))

        if not typeTag:
            return

        typeTag = typeTag[0]

        if typeTag.totalSize != 32:
            raise ValueError('totalLength is not of size 32!')

        if typeTag.dataSize != 4:
            raise ValueError('dataLength is not of size 4!')

        if typeTag.data.getvalue()[::-1] not in TYPES:
            raise ValueError(f'Unknown value: {typeTag.data.getvalue()[::-1]}')

        if typeTag.data.getvalue()[::-1] != getImg3Ident(self.img3).getvalue():
            raise ValueError('TYPE does not match ident!')

        if getSizeOfIOStream(typeTag.padding) != 16:
            raise ValueError('Pad is not of size 16!')

        return True

    def test_DATA(self, iv: BytesIO | None, key: BytesIO | None) -> bool | None:
        dataTag = getTagWithMagic(self.img3, BytesIO(b'DATA'))

        if not dataTag:
            return

        dataTag = dataTag[0]

        kbagTag = getTagWithMagic(self.img3, BytesIO(b'KBAG'))

        if not kbagTag:
            return 

        kbagTag = kbagTag[0]

        hasKASLR = True if int(self.version.split('.')[0]) >= 6 else False
        isKernel = True if self.img3.ident == b'krnl' else False

        oldData = dataTag.data.getvalue() + dataTag.padding.getvalue()
        oldHash = hash(oldData)

        kbagObj = parseKBAG(kbagTag)

        decryptedDataTag, paddingWasZeroed = img3Decrypt(dataTag, kbagObj.aesType, iv, key)
        decryptedData = decryptedDataTag.data.getvalue() + decryptedDataTag.padding.getvalue()
        decryptedHash = hash(decryptedData)

        if oldHash == decryptedHash:
            # Decryption made no impact.
            raise ValueError('Decryption made no impact. Assuming decryption did not work!')

        if isKernel:
            # Decompress
            decryptedDataTag = handleKernelData(decryptedDataTag, hasKASLR)

            # Compress
            decryptedDataTag = handleKernelData(decryptedDataTag, hasKASLR)

        encryptedDataTag = img3Encrypt(decryptedDataTag, kbagObj.aesType, iv, key, paddingWasZeroed)

        # Required
        newImg3 = replaceTagInImg3Obj(self.img3, encryptedDataTag)

        newDataTag = getTagWithMagic(newImg3, BytesIO(b'DATA'))

        if not newDataTag:
            return

        newDataTag = newDataTag[0]

        newData = newDataTag.data.getvalue() + newDataTag.padding.getvalue()
        newHash = hash(newData)

        return oldHash == newHash
    
    def test_VERS(self) -> bool | None:
        versTag = getTagWithMagic(self.img3, BytesIO(b'VERS'))

        if not versTag:
            return

        versTag = versTag[0]
        iBootStrSize = unpack('<I', getBufferAtIndex(versTag.data, 0, 4).getvalue())[0]
        _ = getBufferAtIndex(versTag.data, 4, iBootStrSize)

        return True

    def test_SEPO(self) -> bool | None:
        sepoTag = getTagWithMagic(self.img3, BytesIO(b'SEPO'))

        if not sepoTag:
            return

        sepoTag = sepoTag[0]

        if not isAligned(sepoTag.totalSize, 4):
            raise ValueError('totalLenth is not 4 byte aligned!')

        if sepoTag.dataSize != 4:
            raise ValueError('dataLength is not of size 4!')

        if getSizeOfIOStream(sepoTag.data) != 4:
            raise ValueError('data is not of size 4!')

        if getSizeOfIOStream(sepoTag.padding) >= 1 and not isAligned(getSizeOfIOStream(sepoTag.padding), 4):
            raise ValueError('pad is not of size 0 but is not 4 byte aligned!')

        sepo = unpack('<I', sepoTag.data.getvalue())[0]

        if sepo not in SEPOS:
            raise ValueError(f'Bad value: {sepo}')

        return True

    def test_CHIP(self) -> bool | None:
        chipTag = getTagWithMagic(self.img3, BytesIO(b'CHIP'))

        if not chipTag:
            return

        chipTag = chipTag[0]

        chip = unpack('<I', chipTag.data.getvalue())[0]

        if chip not in CHIPS:
            raise ValueError(f'Bad value: {chip}')

        return True

    def test_BORD(self) -> bool | None:
        bordTag = getTagWithMagic(self.img3, BytesIO(b'BORD'))

        if not bordTag:
            return

        bordTag = bordTag[0]

        board = unpack('<I', bordTag.data.getvalue())[0]

        if board not in BORDS:
            raise ValueError(f'Bad value: {board}')

        return True

    def test_KBAG(self) -> bool | None:
        kbags = getTagWithMagic(self.img3, BytesIO(b'KBAG'))

        if not kbags:
            return

        for kbagTag in kbags:
            parseKBAG(kbagTag)

        return True

    def test_SALT(self) -> bool | None:
        saltTag = getTagWithMagic(self.img3, BytesIO(b'SALT'))

        if not saltTag:
            return

        saltTag = saltTag[0]

        pass

    def test_ECID(self) -> bool | None:
        ecidTag = getTagWithMagic(self.img3, BytesIO(b'ECID'))

        if not ecidTag:
            return

        ecidTag = ecidTag[0]

        pass

    def test_SHSH(self) -> bool | None:
        shshTag = getTagWithMagic(self.img3, BytesIO(b'SHSH'))

        if not shshTag:
            return

        shshTag = shshTag[0]

        if shshTag.totalSize != 140:
            raise ValueError('totalLength is not of size 140!')

        if shshTag.dataSize != 128:
            raise ValueError('dataLength is not of size 128!')

        if getSizeOfIOStream(shshTag.data) != 128:
            raise ValueError('data is not of size 128!')

        if getSizeOfIOStream(shshTag.padding) >= 1:
            raise ValueError('pad is not of size 0!')
        
        return verifySHSH(self.img3)

    def test_CERT(self) -> bool | None:
        certTag = getTagWithMagic(self.img3, BytesIO(b'CERT'))

        if not certTag:
            return

        certTag = certTag[0]
        _ = decodeDER(certTag.data.getvalue())

        return True

    def test_CEPO(self) -> bool | None:
        cepoTag = getTagWithMagic(self.img3, BytesIO(b'CEPO'))

        if not cepoTag:
            return

        cepoTag = cepoTag[0]

        pass

    def test_SDOM(self) -> bool | None:
        sdomTag = getTagWithMagic(self.img3, BytesIO(b'SDOM'))

        if not sdomTag:
            return

        sdomTag = sdomTag[0]

        pass

    def test_PROD(self) -> bool | None:
        prodTag = getTagWithMagic(self.img3, BytesIO(b'PROD'))

        if not prodTag:
            return

        prodTag = prodTag[0]

        pass

    def test_head(self) -> bool:
        ident = getImg3Ident(self.img3).read(4)

        if ident not in TYPES:
            raise TypeError(f'Bag ident: {ident}')

        typeTag = getTagWithMagic(self.img3, BytesIO(b'TYPE'))

        # Some images like ramdisk don't have a TYPE tag!
        if typeTag:
            typeTag = typeTag[0]
            typeIdent = typeTag.data.getvalue()[::-1]

            if typeIdent != ident:
                raise ValueError('TYPE does not match head identity!')

        fullSize = IMG3_HEAD_SIZE
        sigCheckArea = 0

        tagsIgnore = (b'SHSH', b'CERT')

        for tag in self.img3.tags:
            if getTagMagic(tag).read(4) not in tagsIgnore:
                sigCheckArea += tag.totalSize

            fullSize += tag.totalSize

        sizeNoPack = fullSize - IMG3_HEAD_SIZE

        if getImg3FullSize(self.img3) != fullSize:
            raise ValueError('fullSize does not match!')

        if getImg3SizeNoPack(self.img3) != sizeNoPack:
            raise ValueError('sizeNoPack does not match!')

        if getImg3SigCheckArea(self.img3) != sigCheckArea:
            raise ValueError('sigCheckArea does not match!')

        return True

def setupInfo(ipswPath: str) -> dict:
    ipsw_contents = getPaths(ipswPath)
    info = {}
    current_version = None
    client = Client()

    for path in ipsw_contents:
        if path.is_dir():
            continue

        current_version = path.parts[1]

        if current_version not in info:
            info[current_version] = {
                'files': [],
                'keys': None,
                'info': None
            }

        if 'Restore.plist' in path.parts:
            manifest = readRestorePlist(path.read_bytes())
            info[current_version]['info'] = manifest

            version_info = info[current_version]['info'][current_version]
            device = version_info['device']
            buildid = version_info['buildid']

            info[current_version]['keys'] = getKeys(client, device, buildid)

        if current_version not in path.parts:
            continue

        info[current_version]['files'].append(path)

    return info


def initImg3s(ipswPath: str):
    info = setupInfo(ipswPath)

    for version in info:
        files = info[version]['files']
        info[version]['img3s'] = {}

        for file in files:
            try:
                img3Obj = readImg3(BytesIO(file.read_bytes()))
            except ValueError:
                continue
            except Exception:
                raise

            if info[version]['keys']:
                for thing in info[version]['keys']:
                    if thing.filename != file.name:
                        continue

                    info[version]['img3s'][file] = {
                        'obj': img3Obj,
                        'iv': BytesIO(thing.iv),
                        'key': BytesIO(thing.key)
                    }

    return info


def go(ipswPath: str, jsonPath: str) -> None:
    stuff = initImg3s(ipswPath)
    results = {}

    for version in stuff:
        if version not in results:
            results[version] = {}

        for path in stuff[version]['img3s']:
            img3Obj = stuff[version]['img3s'][path]['obj']
            iv = stuff[version]['img3s'][path]['iv']
            key = stuff[version]['img3s'][path]['key']

            test = Img3Test(img3Obj, version)
            ident = getImg3Ident(img3Obj).read(4).decode()

            if ident not in results[version]:
                results[version][ident] = {}

            results[version][ident]['TYPE'] = test.test_TYPE()
            results[version][ident]['DATA'] = test.test_DATA(iv, key)
            results[version][ident]['VERS'] = test.test_VERS()
            results[version][ident]['SEPO'] = test.test_SEPO()
            results[version][ident]['CHIP'] = test.test_CHIP()
            results[version][ident]['BORD'] = test.test_BORD()
            results[version][ident]['KBAG'] = test.test_KBAG()
            results[version][ident]['SALT'] = test.test_SALT()
            results[version][ident]['ECID'] = test.test_ECID()
            results[version][ident]['SHSH'] = test.test_SHSH()
            results[version][ident]['CERT'] = test.test_CERT()
            # results[version][ident]['CEPO'] = test.test_CEPO()
            # results[version][ident]['SDOM'] = test.test_SDOM()
            # results[version][ident]['PROD'] = test.test_PROD()
            results[version][ident]['head'] = test.test_head()

    writeJSON(jsonPath, results)


def main(args: list) -> None:
    argc = len(args)

    if argc != 3:
        print('Usage: <ipsw path> <json path>')
        return

    go(args[1], args[2])


if __name__ == '__main__':
    main(sys.argv)
