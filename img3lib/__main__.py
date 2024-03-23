
from argparse import ArgumentParser

from .const import LZSS_MODE_COMPRESS, LZSS_MODE_DECOMPRESS
from .img3 import Img3Crypt
from .lzsscode import LZSS
from .utils import readBinaryFile, writeBinaryFile


def main() -> None:
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-o', nargs=1)
    parser.add_argument('-iv', nargs=1)
    parser.add_argument('-k', nargs=1)
    parser.add_argument('--data', nargs=1)
    parser.add_argument('--lzss', action='store_true')
    parser.add_argument('--kaslr', action='store_true')

    args = parser.parse_args()

    input_data = None
    output_data = None
    data = None
    iv = None
    key = None

    if args.i:
        input_data = readBinaryFile(args.i[0])

    if args.data:
        data = readBinaryFile(args.data[0])

    if args.iv:
        iv = args.iv[0]

    if args.k:
        key = args.k[0]

    if args.o:
        if input_data is None:
            print('Specified to write data, but input file was not set!')

        img3file = Img3Crypt(input_data)

        if data is None and iv and key:
            output_data = img3file.decrypt(iv, key)

            if args.lzss:
                output_data = LZSS(output_data, LZSS_MODE_DECOMPRESS).decompress()

        if data:
            if args.lzss:
                prelinkVersion = 1 if args.kaslr else 0
                output_data = LZSS(data, LZSS_MODE_COMPRESS).compress(prelinkVersion)

            if iv and key:
                # output_data = img3file.encrypt(iv, key)
                pass

        writeBinaryFile(args.o[0], output_data)


if __name__ == '__main__':
    main()
