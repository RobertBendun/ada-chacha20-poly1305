#!/bin/sh

set -xe

make


# 2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305
echo "0: 50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7" | xxd -r > aad.bin
echo "0: 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f" | xxd -r > key.bin
echo "0: 90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f" | xxd -r >> key.bin
echo "0: 07 00 00 00 40 41 42 43 44 45 46 47" | xxd -r > nonce.bin
printf "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it." > plain.bin

./chacha20_poly1305 aad.bin key.bin nonce.bin plain.bin cipher.bin
