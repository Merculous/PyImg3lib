
from subprocess import Popen, PIPE, STDOUT

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
