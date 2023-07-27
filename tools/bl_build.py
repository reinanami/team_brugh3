#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import hashlib #crying
import os
import pathlib
import shutil
import subprocess
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from binascii import unhexlify
from util import print_hex
from  pwn import *

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootloader Build Tool")
    parser.add_argument(
        "--initial-firmware",
        help="Path to the the firmware binary.",
        default=os.path.join(REPO_ROOT, "firmware/gcc/main.bin"),
    )
    args = parser.parse_args()
    firmware_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(
            f'ERROR: {firmware_path} does not exist or is not a file. You may have to call "make" in the firmware directory.'
        )

    copy_initial_firmware(firmware_path)
    make_bootloader()

# function to generate random byte strings based on a certain number of bytes passed
def generate(number):
    key = os.urandom(number)
    return key

#generate the aes key 
aes_key = generate(16)
#generate a random 16 byte string of characters 
header = generate(16)

# write the aes key and header to the secret file in byte format
with open("secret_build_output.txt", "wb") as file:
    file.write(aes_key + b"\n")
    file.write(header)


# converts binary string to c array so that we can take it in as input, def not warren's stolen code, I'd never do that (not)
def arrayize(binary_string):
    return '{' + ', '.join([hex(char) for char in binary_string]) + '}'


with open("keys.h", "w") as file:#Writes header file
    file.write('#ifndef KEYS_H' + "\n")
    file.write('#define KEY (const uint8_t[]) ' + arrayize(aes_key) + "\n")
    file.write('#define HEADER (const uint8_t[]) ' + arrayize(header) + "\n")
    file.write('#endif')

