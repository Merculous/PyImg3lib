
from argparse import ArgumentParser
from binascii import hexlify

from .img3 import Img3File
from .utils import readBinaryFile, writeBinaryFile, readPlist


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1, help='input file (img3)', metavar='img3')
    parser.add_argument('-o', nargs=1, help='output file', metavar='')

    parser.add_argument('--data', nargs=1, help='data for DATA tag', metavar='')
    parser.add_argument('--diff', nargs=1, help='diff two img3 files', metavar='img3')
    parser.add_argument('--blob', nargs=1, help='sign and personalize an img3', metavar='')

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
    parser.add_argument('--kbag', action='store_true', help='decrypt KBAG(s)')

    parser.add_argument('-iv', nargs=1, metavar='iv')
    parser.add_argument('-k', nargs=1, metavar='key')

    args = parser.parse_args()

    if args.i:
        in_data = readBinaryFile(args.i[0])
        img3file = Img3File(in_data)

        # Set iv and key if user specifies, however not all
        # images are encrypted. Also iOS 10 images should not be
        # encrypted anyway.

        if args.iv and args.k:
            img3file.iv = args.iv[0]
            img3file.key = args.k[0]

        if args.d and args.o:
            data = None

            decrypted = img3file.decrypt()

            if args.lzss:
                data = img3file.handleKernelData(decrypted)
            else:
                data = decrypted

            writeBinaryFile(args.o[0], data)

        elif not args.d and args.data and args.o:
            data = readBinaryFile(args.data[0])

            to_encrypt = None

            if args.lzss:
                to_encrypt = img3file.handleKernelData(data, args.kaslr)
            else:
                to_encrypt = data

            encrypted = img3file.encrypt(to_encrypt)

            img3file.replaceDATA(encrypted)

            new_img3 = img3file.updateImg3Data()

            writeBinaryFile(args.o[0], new_img3)

        elif args.kpwn and args.o:
            isN88 = None

            if args.n72:
                isN88 = False

            elif args.n88:
                isN88 = True

            else:
                print('Please provide either --n72 or --n88!')
                return

            pwned_llb = img3file.do24KPWN(isN88)

            writeBinaryFile(args.o[0], pwned_llb)

        elif args.cert and args.o:
            cert_data = img3file.extractCertificate()

            writeBinaryFile(args.o[0], cert_data)

        elif args.x and args.o:
            data = b''.join(img3file.extractDATA())

            writeBinaryFile(args.o[0], data)

        elif args.a:
            img3file.printImg3Info()

        elif args.diff:
            data = readBinaryFile(args.diff[0])

            new_img3 = Img3File(data)

            img3file.findDifferences(new_img3)

        elif args.v:
            shshValid = img3file.verifySHSH()

            if shshValid is None:
                print('SHSH tag not found. Cannot validate!')
                return

            print(f'SHSH is {"VALID" if shshValid else "INVALID"}')

        elif args.blob and args.o:
            shshBlobs = readPlist(args.blob[0])
            signed = img3file.sign(shshBlobs)
            verify = Img3File(signed).verifySHSH()

            if not verify:
                raise Exception('Failed to sign!')

            return writeBinaryFile(args.o[0], signed)

        elif args.kbag:
            kbags = img3file.prepareKBAGS()

            if not args.d:
                for isRelease, kbag in kbags:
                    print(f'Release: {isRelease}')
                    print(f'KBAG: {hexlify(kbag).decode()}')

                return

            if args.k:
                for isRelease, kbag in kbags:
                    if not isRelease:
                        continue

                    break

                iv, key = img3file.decryptKBAG(kbag, b''.fromhex(args.k[0]))

                print(f'IV: {hexlify(iv).decode()}')
                print(f'Key: {hexlify(key).decode()}')

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
