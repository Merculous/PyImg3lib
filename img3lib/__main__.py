
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
        if args.data and args.o:
            orig = readBinaryFile(args.i[0])
            data = readBinaryFile(args.data[0])

            origImg3 = IMG3(orig)

            newImg3 = origImg3.replaceData(data)

            writeBinaryFile(args.o[0], newImg3)

        else:
            data = readBinaryFile(args.i[0])

            img3file = IMG3(data)

        if args.a:
            img3file.printAllImg3Info()

        elif args.d and args.o:
            decrypted_data = img3file.decrypt(args.iv[0], args.key[0])

            writeBinaryFile(args.o[0], decrypted_data)

    else:
        parser.print_help()


main()
