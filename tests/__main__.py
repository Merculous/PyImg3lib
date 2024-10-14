
import sys
from .test_img3 import main as img3Main


def doTest(args: list):
    img3Main(args)


if __name__ == '__main__':
    doTest(sys.argv)
