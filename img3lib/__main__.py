
from argparse import ArgumentParser

from .img3 import IMG3
from .utils import readBinaryFile, writeBinaryFile


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-o', nargs=1)

    parser.add_argument('--aes', nargs=1)
    parser.add_argument('--data', nargs=1)

    parser.add_argument('-a', action='store_true')
    parser.add_argument('-c', action='store_true')
    parser.add_argument('-d', action='store_true')

    parser.add_argument('--cert', action='store_true')
    parser.add_argument('--n8824k', action='store_true')

    parser.add_argument('-iv', nargs=1)
    parser.add_argument('-key', nargs=1)

    args = parser.parse_args()

    if args.i:
        in_data = readBinaryFile(args.i[0])

        img3file = IMG3(in_data)

        if args.iv:
            img3file.iv = args.iv[0]

        if args.key:
            img3file.key = args.key[0]

        if args.data and args.o:
            raw_data = readBinaryFile(args.data[0])

            if args.aes:
                img3file.replaceData(raw_data, args.aes[0])
            else:
                img3file.replaceData(raw_data)

            writeBinaryFile(args.o[0], img3file.newData)

        elif args.cert and args.o:
            cert_data = img3file.extractCertificate()

            writeBinaryFile(args.o[0], cert_data)

        elif args.a:
            img3file.printAllImg3Info()

        elif args.d and args.o:
            decrypted_data = None

            if args.aes:
                decrypted_data = img3file.decrypt(args.aes[0])
            else:
                decrypted_data = img3file.decrypt()

            writeBinaryFile(args.o[0], decrypted_data)

        elif args.n8824k and args.o:
            img3file.do3GSLLBHax()

            writeBinaryFile(args.o[0], img3file.data)

    else:
        parser.print_help()


main()
