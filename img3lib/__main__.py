
from argparse import ArgumentParser

from .img3 import Img3File
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

    in_data = readBinaryFile(args.i[0]) if args.i else None

    iv = args.iv[0] if args.iv else None
    key = args.k[0] if args.k else None

    img3file = Img3File(in_data, iv, key)

    if args.o:
        if args.d:
            # Decryption

            decrypted = img3file.decrypt()

            data = None

            if args.lzss:
                data = img3file.decompress(decrypted)

            else:
                data = decrypted

            writeBinaryFile(args.o[0], data)

        pass

    else:
        parser.print_help()

main()
