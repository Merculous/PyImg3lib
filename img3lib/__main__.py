
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

        img3file = IMG3(data)

        if args.iv and args.key:
            data_decrypted = img3file.decrypt(args.iv[0], args.key[0])

            with open('decryptTest.bin', 'wb') as f:
                f.write(data_decrypted)

    else:
        parser.print_help()

main()
