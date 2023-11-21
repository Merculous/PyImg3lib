
from argparse import ArgumentParser

from .img3 import IMG3


def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)
    parser.add_argument('-iv', nargs=1)
    parser.add_argument('-key', nargs=1)

    args = parser.parse_args()

    if args.i:
        with open(args.i[0], 'rb') as f:
            data = f.read()

        if args.iv and args.key:
            img3file = IMG3(data, args.iv[0], args.key[0])

            decrypted = img3file.decryptKernel()
            decompressed = img3file.decompressKernel(decrypted)

            with open('decompressed.bin', 'wb') as f:
                f.write(decompressed)

    else:
        parser.print_help()


main()
