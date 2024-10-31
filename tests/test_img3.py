
import json
import plistlib
import sys
from pathlib import Path

from img3lib.img3 import Img3File
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
    else:
        return keyData


def writeJSON(path, data) -> None:
    with open(path, 'w') as f:
        json.dump(data, f)


class Img3Test:
    def __init__(self, img3: Img3File, version: str) -> None:
        self.img3 = img3
        self.version = version

    def test_DATA(self) -> bool:
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
            except Exception:
                continue

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
            results[version] = []

        for img3 in stuff[version]['img3s']:
            if not img3.iv and not img3.key:
                # We're likely hitting extra img3 (img3 for other devices)
                if stuff[version]['keys']:
                    continue

            test = Img3Test(img3, version)

            testResult = (
                img3.ident.decode(),
                test.test_DATA()
            )

            results[version].append(testResult)

    writeJSON(jsonPath, results)


def main(args: list) -> None:
    argc = len(args)

    if argc != 3:
        print('Usage: <ipsw path> <json path>')
        return

    go(args[1], args[2])


if __name__ == '__main__':
    main(sys.argv)
