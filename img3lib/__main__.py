
from argparse import ArgumentParser

from .img3 import IMG3
from .utils import readBinaryFile, writeBinaryFile


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-o', nargs=1)

    parser.add_argument('-a', action='store_true')
    parser.add_argument('-d', action='store_true')

    parser.add_argument('-iv', nargs=1)
    parser.add_argument('-key', nargs=1)

    args = parser.parse_args()

    if args.i:
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
