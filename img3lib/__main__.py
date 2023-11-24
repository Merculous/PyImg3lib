
from argparse import ArgumentParser

from .img3 import IMG3
from .utils import readBinaryFile


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)

    parser.add_argument('-a', action='store_true')

    parser.add_argument('-iv', nargs=1)
    parser.add_argument('-key', nargs=1)

    args = parser.parse_args()

    if args.i:
        data = readBinaryFile(args.i[0])

        img3file = IMG3(data)

        if args.a:
            img3file.printAllImg3Info()

    else:
        parser.print_help()


main()
