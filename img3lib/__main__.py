
from argparse import ArgumentParser

from .img3 import IMG3
from .utils import readBinaryFile, writeBinaryFile


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-o', nargs=1)

    parser.add_argument('--data', nargs=1)

    parser.add_argument('-a', action='store_true')
    parser.add_argument('-c', action='store_true')
    parser.add_argument('-d', action='store_true')

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

            newImg3 = img3file.replaceData(raw_data)

            writeBinaryFile(args.o[0], newImg3)

        if args.a:
            img3file.printAllImg3Info()

        elif args.d and args.o:
            decrypted_data = img3file.decrypt()

            writeBinaryFile(args.o[0], decrypted_data)

    else:
        parser.print_help()


main()
