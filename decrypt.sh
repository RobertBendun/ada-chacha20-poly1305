#!/bin/sh


EXEC="./chacha20_poly1305_aead"
gnatmake main.adb "-j$(nproc)" -o "$EXEC"

"$EXEC" decrypt aad.bin key.bin nonce.bin cipher.bin decrypted.bin tag.bin
