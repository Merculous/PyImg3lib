
from argparse import ArgumentParser

from .img3 import Img3File
from .lzsscode import LZSS
from .utils import readBinaryFile, writeBinaryFile


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-o', nargs=1)

    parser.add_argument('--data', nargs=1)

    parser.add_argument('-a', action='store_true')
    parser.add_argument('-c', action='store_true')
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
                    data = LZSS(decrypted).go()
                else:
                    data = decrypted

                writeBinaryFile(args.o[0], data)

    else:
        parser.print_help()

main()
