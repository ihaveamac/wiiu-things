#!/usr/bin/env python3

# encrypted titlekey is decrypted with the Wii U Common Key
# with IV being TID + 0x00 padding

# contents are decrypted with the decrypted titlekey
# with IV being all 0x00, or index bytes + 0x00 padding

import binascii
import glob
import hashlib
import itertools
import math
import os
import struct
import sys
from Crypto.Cipher import AES

# put the common key here to decrypt things
wiiu_common_key = ""

##########################

wiiu_common_key_hash = hashlib.sha1(wiiu_common_key.encode('utf-8').upper())
if wiiu_common_key_hash.hexdigest() != 'e3fbc19d1306f6243afe852ab35ed9e1e4777d3a':
    sys.exit("Wrong Wii U Common Key. Place the correct one in the script.")

ckey = binascii.unhexlify(wiiu_common_key)

readsize = 8 * 1024 * 1024

if not os.path.isfile("tmd"):
    sys.exit("No TMD was found.")


def showprogress(val, maxval):
    # crappy workaround I bet, but print() didn't do what I wanted
    minval = min(val, maxval)
    sys.stdout.write("\r- {:>5.1f}% {:>10} / {}".format((minval / maxval) * 100, minval, maxval))
    sys.stdout.flush()

# find title id and content id
title_id = b""
contents = []
content_count = 0
tmd_index = b""  # some weird thing used for the IV
with open(glob.glob("tmd*")[0], "rb") as tmd:
    tmd.seek(0x18C)
    title_id = tmd.read(0x8)
    tmd.seek(0x1DE)
    content_count = struct.unpack(">H", tmd.read(0x2))[0]
    tmd.seek(0x204)
    tmd_index = tmd.read(0x2)[::-1]
    for c in range(content_count):
        tmd.seek(0xB04 + (0x30 * c))
        content_id = binascii.hexlify(tmd.read(0x4)).decode('utf-8')
        tmd.seek(0xB0C + (0x30 * c))
        content_size = struct.unpack(">Q", tmd.read(0x8))[0]
        tmd.seek(0xB14 + (0x30 * c))
        content_hash = tmd.read(0x14)
        contents.append([content_id, content_size, content_hash])

print("Title ID:               " + binascii.hexlify(title_id).decode('utf-8').upper())

# find encrypted titlekey
encrypted_titlekey = b""
if os.path.isfile("cetk"):
    with open("cetk", "rb") as cetk:
        cetk.seek(0x1BF)
        encrypted_titlekey = cetk.read(0x10)
elif len(sys.argv) > 1:
    encrypted_titlekey = binascii.unhexlify(sys.argv[1])
else:
    sys.exit("Missing cetk. Please add an argument containing the encrypted titlekey.")

print("Encrypted Titlekey:     " + binascii.hexlify(encrypted_titlekey).decode('utf-8').upper())

# decryption fun
cipher_titlekey = AES.new(ckey, AES.MODE_CBC, title_id + (b"\0" * 8))
decrypted_titlekey = cipher_titlekey.decrypt(encrypted_titlekey)
print("Decrypted Titlekey:     " + binascii.hexlify(decrypted_titlekey).decode('utf-8').upper())

do_hash = True  # this is disabled after hashing the first content
for c in contents:
    print("Decrypting {}...".format(c[0]))
    cipher_content = AES.new(decrypted_titlekey, AES.MODE_CBC, tmd_index + b"\0" * 14)
    content_hash = hashlib.sha1()
    left = c[1]  # set to current size

    # actually for those that have .h3 files, the hash in the tmd is of the h3
    # but what's in the h3 then? it's usually the length of one or two SHA-1 hashes
    # but I don't know what exactly it's a hash of yet
    with open(c[0], "rb") as encrypted:
        with open(c[0] + ".dec", "wb") as decrypted:
            for __ in itertools.repeat(0, int(math.floor((c[1] / readsize)) + 1)):
                to_read = min(readsize, left)
                tmp_enc = encrypted.read(to_read)
                tmp_dec = cipher_content.decrypt(tmp_enc)
                if do_hash:
                    content_hash.update(tmp_dec)
                decrypted.write(tmp_dec)
                left -= readsize
                showprogress(c[1] - left, c[1])
                if left <= 0:
                    print("")
                    break
    if do_hash:
        if c[2] == content_hash.digest():
            print("Hash valid (only first content is checked)")
        else:
            print("Hash mismatch! (only first content is checked)")
            print(" > TMD:    " + binascii.hexlify(c[2]).decode('utf-8').upper())
            print(" > Result: " + content_hash.hexdigest().upper())

    do_hash = False
