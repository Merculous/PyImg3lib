
from argparse import ArgumentParser

from .img3 import Img3File
from .utils import readBinaryFile, writeBinaryFile


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-o', nargs=1)

    parser.add_argument('--data', nargs=1)
    parser.add_argument('--diff', nargs=1)

    parser.add_argument('-a', action='store_true')
    parser.add_argument('-d', action='store_true')

    parser.add_argument('--cert', action='store_true')
    parser.add_argument('--n8824k', action='store_true')
    parser.add_argument('--lzss', action='store_true')

    parser.add_argument('-iv', nargs=1)
    parser.add_argument('-k', nargs=1)

    args = parser.parse_args()

    if args.i:
        in_data = readBinaryFile(args.i[0])

        img3file = Img3File(in_data)

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

            if not args.d and args.data and args.o:
                data = readBinaryFile(args.data[0])

                to_encrypt = None

                if args.lzss:
                    to_encrypt = img3file.handleKernelData(data)
                else:
                    to_encrypt = data

                encrypted = img3file.encrypt(to_encrypt)

                img3file.replaceDATA(encrypted)

                new_img3 = img3file.updateImg3Data()

                writeBinaryFile(args.o[0], new_img3)

        elif args.n8824k and args.o:
            pwned_llb = img3file.do24KPWN()

            writeBinaryFile(args.o[0], pwned_llb)

        elif args.cert and args.o:
            cert_data = img3file.extractCertificate()

            writeBinaryFile(args.o[0], cert_data)

        elif args.a:
            img3file.printImg3Info()

        elif args.diff:
            data = readBinaryFile(args.diff[0])

            new_img3 = Img3File(data)

            img3file.findDifferences(new_img3)

    else:
        parser.print_help()


main()
