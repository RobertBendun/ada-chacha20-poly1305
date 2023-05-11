#!/bin/sh


if [ ! -f "$1" ]; then
	echo "usage: $(basename "$0") <file to encrypt>"
	exit 2
fi

EXEC="./chacha20_poly1305_aead"
gnatmake main.adb "-j$(nproc)" -o "$EXEC"

head -c 32 /dev/random > key.bin
head -c 12 /dev/random > nonce.bin
printf "%s" "$(file --mime-type "$1" | cut -d' ' -f2)" > aad.bin
cp "$1" plain.bin

"$EXEC" aad.bin key.bin nonce.bin "$1" cipher.bin > tag.txt

tar -czf encrypted.tar.gz key.bin nonce.bin aad.bin tag.txt cipher.bin
echo "All artifacts has ben archived into encrypted.tar.gz"
