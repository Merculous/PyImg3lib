#!/usr/bin/env python3

import json
import plistlib
from pathlib import Path
from zlib import crc32

from img3lib.img3 import Img3File
from lykos.client import Client


IPSW_PATH = 'IPSW'


def getPaths(path: str) -> list[Path]:
    return [p for p in Path(path).rglob('*')]


def readManifest(data: bytes) -> dict:
    plist = plistlib.loads(data)
    buildident = plist['BuildIdentities'][0]

    info = {
        plist['ProductVersion']: {
            'device': plist['SupportedProductTypes'][0],
            'buildid': plist['ProductBuildVersion'],
            'codename': buildident['Info']['BuildTrain']
        }
    }

    return info


def getKeys(client: Client, device: str, buildid: str, codename: str) -> dict:
    return client.get_key_data(device, buildid, codename)


def writeJSON(path, data) -> None:
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def test(info: dict):
    results = {}

    for version in info:
        for file in info[version]['files']:
            for name in info[version]['keys']:
                if name.filename not in file.name:
                    continue

                data = file.read_bytes()

                if version not in results:
                    results[version] = {}

                if name.name not in results[version]:
                    results[version][name.name] = {
                        'failed': False,
                        'origCRC': None,
                        'newCRC': None
                    }

                try:
                    img3 = Img3File(data, name.iv, name.key)
                except Exception:
                    continue

                decrypted = img3.decrypt()

                if img3.ident == b'krnl':
                    versionMinor = int(version[0])
                    kASLR = True if versionMinor >= 6 else False

                    # Decompress
                    decrypted = img3.handleKernelData(decrypted, kASLR)

                    # Compress
                    decrypted = img3.handleKernelData(decrypted, kASLR)

                encrypted = img3.encrypt(decrypted)

                img3.replaceDATA(encrypted)
                new_img3 = img3.updateImg3Data()

                results[version][name.name]['origCRC'] = crc32(data)
                results[version][name.name]['newCRC'] = crc32(new_img3)

                origCRC = results[version][name.name]['origCRC']
                newCRC = results[version][name.name]['newCRC']

                results[version][name.name]['failed'] = True if origCRC != newCRC else False

                if results[version][name.name]['failed']:
                    print(f'{version}: {name.name}')

    writeJSON('test_results.json', results)


def go():
    ipsw_contents = getPaths(IPSW_PATH)
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

        if 'BuildManifest.plist' in path.parts:
            manifest = readManifest(path.read_bytes())
            info[current_version]['info'] = manifest

            version_info = info[current_version]['info'][current_version]
            device = version_info['device']
            buildid = version_info['buildid']
            codename = version_info['codename']

            info[current_version]['keys'] = getKeys(client, device, buildid, codename)

        if current_version not in path.parts:
            continue

        info[current_version]['files'].append(path)

    test(info)


if __name__ == '__main__':
    go()
