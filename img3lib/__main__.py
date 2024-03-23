
from argparse import ArgumentParser

from .const import LZSS_MODE_COMPRESS, LZSS_MODE_DECOMPRESS
from .img3 import Img3Crypt
from .lzsscode import LZSS
from .utils import readBinaryFile, writeBinaryFile


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-o', nargs=1)

    parser.add_argument('-d', action='store_true')

    parser.add_argument('-iv', nargs=1)
    parser.add_argument('-k', nargs=1)

    parser.add_argument('--data', nargs=1)

    parser.add_argument('--lzss', action='store_true')
    parser.add_argument('--compress', action='store_true')
    parser.add_argument('--decompress', action='store_true')

    args = parser.parse_args()

    if args.i:
        input_data = readBinaryFile(args.i[0])
        img3file = Img3Crypt(input_data)

        if args.d and args.iv and args.k:
            decrypted = img3file.decrypt(args.iv[0], args.k[0])

            if args.o:
                output_data = b''

                if args.lzss:
                    lzss_obj = LZSS(decrypted, LZSS_MODE_DECOMPRESS)
                    output_data += lzss_obj.decompress()

                writeBinaryFile(args.o[0], output_data)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
