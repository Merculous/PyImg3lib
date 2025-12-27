
from argparse import ArgumentParser
from pathlib import Path

from binpatch.io import readBytesFromPath, writeBytesToPath

from .img3 import (KBAG_CRYPT_STATE_PRODUCTION, dataTagPaddingIsZeroed,
                   decryptKBAG, findDifferencesBetweenTwoImg3s,
                   getNestedImageInCERT, getTagWithMagic, handleKernelData,
                   img3Decrypt, img3Encrypt, img3ToBytes, make24KPWNLLB,
                   makeTag, parseKBAG, printImg3Info, printKBAG, readImg3,
                   replaceTagInImg3Obj, signImg3, verifySHSH)
from .utils import readPlist


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', help='input file (img3)', metavar='img3', type=Path)
    parser.add_argument('-o', help='output file', metavar='', type=Path)
 
    parser.add_argument('--data', help='data for DATA tag', metavar='', type=Path)
    parser.add_argument('--diff', help='diff two img3 files', metavar='img3', type=Path)
    parser.add_argument('--blob', help='sign and personalize an img3', metavar='', type=Path)
    parser.add_argument('--manifest', help='BuildManifest.plist (used when signing)', metavar='', type=Path)

    parser.add_argument('-a', action='store_true', help='print all img3 info')
    parser.add_argument('-d', action='store_true', help='decrypt')
    parser.add_argument('-x', action='store_true', help='extract DATA')
    parser.add_argument('-v', action='store_true', help='verify SHSH')

    parser.add_argument('--cert', action='store_true', help='extract CERT data')
    parser.add_argument('--kpwn', action='store_true', help='make a 24KPWN LLB')
    parser.add_argument('--n72', action='store_true', help='N72/iPod use with --kpwn')
    parser.add_argument('--n88', action='store_true', help='N88/3GS use with --kpwn')
    parser.add_argument('--lzss', action='store_true', help='(de)compress kernel DATA')
    parser.add_argument('--kaslr', action='store_true', help='kernel supports kASLR (iOS 6+)')
    parser.add_argument('--kbag', action='store_true', help='print KBAG(s)')
    parser.add_argument('--nested', action='store_true', help='print nested Img3 in CERT')
    parser.add_argument('--gid', action='store_true', help='Decrypt using GID key')

    parser.add_argument('-iv', metavar='iv', type=str)
    parser.add_argument('-k', metavar='key', type=str)

    args = parser.parse_args()

    if not args.i:
        return parser.print_help()

    inData = readBytesFromPath(args.i)
    img3Obj = readImg3(inData)

    if args.d and args.o:
        dataTag = getTagWithMagic(img3Obj, b'DATA')

        if not dataTag:
            return print('This image does not contain a DATA tag!')

        dataTag = dataTag[0]
        kbagTag = getTagWithMagic(img3Obj, b'KBAG')

        if not kbagTag:
            return print('This image does not contain a KBAG tag!')

        kbagObj = None

        for kbag in kbagTag:
            kbagObj = parseKBAG(kbag)

            if kbagObj.cryptState != KBAG_CRYPT_STATE_PRODUCTION:
                continue

            kbagTag = kbag
            break

        if not kbagObj:
            raise ValueError('KBAG object is NONE!')

        iv = None if not args.iv else b''.fromhex(args.iv)
        key = None if not args.k else b''.fromhex(args.k)

        if args.gid:
            iv = b'\x00' * 16
            kbagObj = decryptKBAG(kbagTag, key)
            
            iv = kbagObj.iv
            key = kbagObj.key

        decryptedDataTag, _ = img3Decrypt(dataTag, kbagObj.aesType, iv, key)

        if args.lzss:
            decryptedDataTag = handleKernelData(decryptedDataTag)

        return writeBytesToPath(args.o, decryptedDataTag.data)

    if args.data and args.o:
        newData = readBytesFromPath(args.data)
        newDataTag = makeTag(b'DATA', newData)

        if args.lzss:
            newDataTag = handleKernelData(newDataTag, args.kaslr)

        if args.iv and args.k:
            kbagTag = getTagWithMagic(img3Obj, b'KBAG')

            if not kbagTag:
                return print('This image does not contain a KBAG tag!')

            kbagTag = kbagTag[0]
            kbagObj = parseKBAG(kbagTag)
            origDataTag = getTagWithMagic(img3Obj, b'DATA')

            if not origDataTag:
                return print('This image does not contain a DATA tag!')

            origDataTag = origDataTag[0]
            origDataPaddingZeroed = dataTagPaddingIsZeroed(origDataTag)
            newDataTag = img3Encrypt(newDataTag, kbagObj.aesType, b''.fromhex(args.iv), b''.fromhex(args.k), origDataPaddingZeroed)

        newImg3 = replaceTagInImg3Obj(img3Obj, newDataTag)
        img3Data = img3ToBytes(newImg3)
        return writeBytesToPath(args.o, img3Data)

    if args.diff:
        secondImg3Data = readBytesFromPath(args.diff)
        secondImg3 = readImg3(secondImg3Data)
        return findDifferencesBetweenTwoImg3s(img3Obj, secondImg3)

    if args.a and not args.cert:
        return printImg3Info(img3Obj)

    if args.o and args.cert:
        certTag = getTagWithMagic(img3Obj, b'CERT')

        if not certTag:
            return print('This image does not contain a CERT tag!')

        certTag = certTag[0]
        return writeBytesToPath(args.o, certTag.data)

    if args.o and args.x:
        dataTag = getTagWithMagic(img3Obj, b'DATA')

        if not dataTag:
            return print('This image does not contain a DATA tag!')

        dataTag = dataTag[0]
        return writeBytesToPath(args.o, dataTag.data)

    if args.v:
        shshValid = verifySHSH(img3Obj)

        if shshValid is None:
            print('This image does not contain a CERT or SHSH tag!')

        elif shshValid is True:
            print('Image: Valid!')

        elif shshValid is False:
            print('Image: Invalid!')

        else:
            print('Unknown SHSH verify outcome!')

        return

    if args.kbag:
        kbagTags = getTagWithMagic(img3Obj, b'KBAG')

        if not kbagTags:
            return print('This image does not contain a KBAG tag!')

        for tag in kbagTags:
            printKBAG(tag)

        return

    if args.kpwn and args.o:
        kpwnImg3 = make24KPWNLLB(img3Obj, args.n72, args.n88)
        return writeBytesToPath(args.o, img3ToBytes(kpwnImg3))

    if args.blob and args.manifest and args.o:
        blobData = readPlist(args.blob)
        manifestData = readPlist(args.manifest)
        signedImg3 = signImg3(img3Obj, blobData, manifestData)
        img3Data = img3ToBytes(signedImg3)
        return writeBytesToPath(args.o, img3Data)

    if args.cert and args.nested:
        certTag = getTagWithMagic(img3Obj, b'CERT')

        if not certTag:
            return print('This image does not contain a CERT tag!')

        certTag = certTag[0]
        nestedImg3 = getNestedImageInCERT(certTag)
        
        if nestedImg3:
            printImg3Info(nestedImg3)
        else:
            print('CERT does not have a nested Img3!')

        return


if __name__ == '__main__':
    main()
