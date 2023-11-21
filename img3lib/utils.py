
from subprocess import Popen, PIPE, STDOUT
from zlib import adler32


def aes_decrypt(data, iv, key):
    args = (
        'openssl',
        'enc',
        '-aes-256-cbc',
        '-d',
        '-nopad',
        '-iv',
        iv,
        '-K',
        key
    )

    cmd = Popen(args, stdout=PIPE, stdin=PIPE, stderr=STDOUT)

    cmd_stdout = cmd.communicate(data)[0]

    return cmd_stdout


def getKernelChecksum(data):
    return adler32(data)
