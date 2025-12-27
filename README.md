
This code will interact with Apple's img3 data.

# Credits

axi0mX: ipwndfu (img3 stuff) \
plzdonthaxme (plx): General help \
m1stadev: lzss fixes \
planetbeing: 24KPWN LLB Payload

# Usage
Remember an input img3 is always required

* -d -o (DATA.bin) (Decrypt an img3 and output its DATA tag)
    - --lzss (Decompress a kernelcache DATA tag)
    - -iv IV (Decryption)
    - -k key (Decryption)
    - --gid (Decryption with GID key)

* --data (DATA.bin) -o (output.img3) (Create a new img3 with custom DATA)
    - --lzss (Compress a kernelcache DATA tag)
    - -iv IV (Encryption)
    - -k Key (Encryption)

* --diff (other.img3) (Find differences between two img3's)

* -a (Print img3 info)

* -o (CERT.bin) --cert (Output CERT data to a file)

* -o (DATA.bin) -x (Extract DATA tag to a file)

* -v (Verify SHSH tag)

* --kbag (Print KBAG tag info)

* --kpwn --n72/--n88 (iPod/iPhone) -o (24KPWN_LLB.img3) (Create a 24KPWN LLB)

* --blob (SHSH file.shsh2) --manifest (BuildManifest.plist) -o (SIGNED.img3) (Sign an img3 with a SHSH2 file)

* --cert --nested (Print img3 within CERT)

# Documentation and extra info
I'm too lazy to write docs, however I'm not really working on this library anymore (for the moment) \
Please refer to the DeepWiki page about this project here: https://deepwiki.com/Merculous/PyImg3lib
