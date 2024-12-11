
import json
import plistlib
import sys
from pathlib import Path

from img3lib.img3 import AlignmentError, Img3File, BadMagic, SizeError, TagNotFound, BadSEPOValue
from img3lib.der import decodeDER
from img3lib.utils import formatData, isAligned
from lykos.client import Client
from lykos.errors import PageNotFound


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
    def __init__(self, img3: Img3File, version: str) -> None:
        self.img3 = img3
        self.version = version

    def test_TYPE(self) -> bool | None:
        try:
            typeTag = self.img3.getTagWithMagic(b'TYPE')
        except TagNotFound:
            return
        else:
            typeTag = typeTag[0]

        if typeTag['totalLength'] != 32:
            raise SizeError('totalLength is not of size 32!')

        if typeTag['dataLength'] != 4:
            raise SizeError('dataLength is not of size 4!')

        if typeTag['data'][::-1] not in self.img3.valid_types:
            raise BadMagic(f'Unknown value: {typeTag["data"]}')

        if typeTag['data'][::-1] != self.img3.ident:
            raise BadMagic('TYPE does not match ident!')

        if len(typeTag['pad']) != 16:
            raise SizeError('Pad is not of size 16!')

        return True

    def test_DATA(self) -> bool | None:
        try:
            self.img3.getTagWithMagic(b'DATA')
        except TagNotFound:
            return

        hasKASLR = True if int(self.version.split('.')[0]) >= 6 else False
        isKernel = True if self.img3.ident == b'krnl' else False

        oldData = self.img3.extractDATA()

        decryptedData = self.img3.decrypt()

        if isKernel:
            # Decompress
            decryptedData = self.img3.handleKernelData(decryptedData, hasKASLR)

            # Compress
            decryptedData = self.img3.handleKernelData(decryptedData, hasKASLR)

        encryptedData = self.img3.encrypt(decryptedData)

        # Required
        self.img3.replaceDATA(encryptedData)

        newData = self.img3.extractDATA()

        return hash(oldData) == hash(newData)

    def test_SEPO(self) -> bool | None:
        try:
            sepoTag = self.img3.getTagWithMagic(b'SEPO')
        except TagNotFound:
            return
        else:
            sepoTag = sepoTag[0]

        if not isAligned(sepoTag['totalLength'], 4):
            raise AlignmentError('totalLenth is not 4 byte aligned!')

        if sepoTag['dataLength'] != 4:
            raise SizeError('dataLength is not of size 4!')

        if len(sepoTag['data']) != 4:
            raise SizeError('data is not of size 4!')

        if len(sepoTag['pad']) >= 1 and not isAligned(len(sepoTag['pad']), 4):
            raise SizeError('pad is not of size 0 but is not 4 byte aligned!')

        sepo = formatData('<I', sepoTag['data'], False)[0]

        if sepo not in self.img3.valid_sepos:
            raise BadSEPOValue(f'Bad value: {sepo}')

        return True
    
    def test_KBAG(self) -> bool | None:
        try:
            kbags = self.img3.getTagWithMagic(b'KBAG')
        except TagNotFound:
            return

        for kbag in kbags:
            self.img3.parseKBAGTag(kbag)

        return True

    def test_SHSH(self) -> bool | None:
        try:
            shshTag = self.img3.getTagWithMagic(b'SHSH')
        except TagNotFound:
            return
        else:
            shshTag = shshTag[0]

        if shshTag['totalLength'] != 140:
            raise SizeError('totalLength is not of size 140!')

        if shshTag['dataLength'] != 128:
            raise SizeError('dataLength is not of size 128!')

        if len(shshTag['data']) != 128:
            raise SizeError('data is not of size 128!')

        if len(shshTag['pad']) >= 1:
            raise SizeError('pad is not of size 0!')
        
        return self.img3.verifySHSH()

    def test_CERT(self) -> bool | None:
        try:
            tag = self.img3.getTagWithMagic(b'CERT')
        except TagNotFound:
            return
        else:
            tag = tag[0]

        data = tag['data']
        decodeDER(data)

        return True

    def test_head(self) -> bool:
        head = self.img3.head
        ident = self.img3.ident

        if ident not in self.img3.valid_types:
            raise TypeError(f'Bag ident: {ident}')

        try:
            typeTag = self.img3.getTagWithMagic(b'TYPE')[0]
        except TagNotFound:
            pass
        else:
            typeIdent = typeTag['data'][::-1]

            if typeIdent != ident:
                raise BadMagic('TYPE does not match head identity!')

        fullSize = self.img3.img3_head_size
        sigCheckArea = 0

        tagsIgnore = (b'SHSH'[::-1], b'CERT'[::-1])

        for tag in self.img3.tags:
            if tag['magic'] not in tagsIgnore:
                sigCheckArea += tag['totalLength']

            fullSize += tag['totalLength']

        sizeNoPack = fullSize - self.img3.img3_head_size

        if head['fullSize'] != fullSize:
            raise SizeError('fullSize does not match!')

        if head['sizeNoPack'] != sizeNoPack:
            raise SizeError('sizeNoPack does not match!')

        if head['sigCheckArea'] != sigCheckArea:
            raise SizeError('sigCheckArea does not match!')

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
        keys = info[version]['keys']

        info[version]['img3s'] = []

        for file in files:
            try:
                img3 = Img3File(file.read_bytes())
            except BadMagic:
                continue
            except Exception:
                raise

            if keys:
                for value in keys:
                    if value.filename != file.name:
                        continue

                    img3.iv = value.iv
                    img3.key = value.key

                    break

            info[version]['img3s'].append(img3)

    return info


def go(ipswPath: str, jsonPath: str) -> None:
    stuff = initImg3s(ipswPath)
    results = {}

    for version in stuff:
        if version not in results:
            results[version] = {}

        for img3 in stuff[version]['img3s']:
            if not img3.iv and not img3.key:
                # We're likely hitting extra img3 (img3 for other devices)
                if stuff[version]['keys']:
                    continue

            test = Img3Test(img3, version)
            ident = img3.ident.decode()

            if ident not in results[version]:
                results[version][ident] = {}

            results[version][ident]['TYPE'] = test.test_TYPE()
            results[version][ident]['DATA'] = test.test_DATA()
            results[version][ident]['SEPO'] = test.test_SEPO()
            results[version][ident]['KBAG'] = test.test_KBAG()
            results[version][ident]['SHSH'] = test.test_SHSH()
            results[version][ident]['CERT'] = test.test_CERT()
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
