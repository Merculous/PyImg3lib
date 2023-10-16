
from argparse import ArgumentParser

from .img3 import IMG3

def main():
    parser = ArgumentParser()

    parser.add_argument('-i', nargs=1)

    args = parser.parse_args()

    if args.i:
        with open(args.i[0], 'rb') as f:
            data = f.read()

        img3file = IMG3(data)
        img3_data = img3file.readImg3()

        magic_str = img3_data['magic'].to_bytes(4, 'little').decode()[::-1]
        ident_str = img3_data['ident'].to_bytes(4, 'little').decode()[::-1]

        print(f'Img3 magic: {magic_str}')
        print(f'Fullsize: {img3_data["fullSize"]}')
        print(f'SizeNoPack: {img3_data["sizeNoPack"]}')
        print(f'SigCheckArea: {img3_data["sigCheckArea"]}')
        print(f'Ident: {ident_str}')

        for tag in img3_data['tags']:
            img3file.readTagInfo(tag)

    else:
        parser.print_help()

main()
