#!/usr/bin/env python3

# encrypted titlekey is decrypted with the Wii U Common Key
# with IV being TID + 0x00 padding

# contents are decrypted with the decrypted titlekey
# with IV being all 0x00, or index bytes + 0x00 padding

import binascii
import glob
import itertools
import math
import os
import struct
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA1

# put the common key here to decrypt things
wiiu_common_key = ""

##########################

wiiu_common_key_hash = SHA1.new(wiiu_common_key.encode('utf-8').upper())
if wiiu_common_key_hash.hexdigest() != 'e3fbc19d1306f6243afe852ab35ed9e1e4777d3a':
    sys.exit("Wrong Wii U Common Key. Place the correct one in the script.")

ckey = binascii.unhexlify(wiiu_common_key)

readsize = 8 * 1024 * 1024

if not os.path.isfile("title.tmd"):
    sys.exit("No TMD (title.tmd) was found.")


def show_progress(val, maxval):
    # crappy workaround I bet, but print() didn't do what I wanted
    minval = min(val, maxval)
    sys.stdout.write("\r- {:>5.1f}% {:>10} / {}".format((minval / maxval) * 100, minval, maxval))
    sys.stdout.flush()


def show_chunk(num, count):
    # crappy workaround I bet, but print() didn't do what I wanted
    sys.stdout.write("\r- Chunk {:>5} / {:>5}".format(num + 1, count))
    sys.stdout.flush()

# find title id and content id
title_id = b""
contents = []
content_count = 0
with open(glob.glob("title.tmd*")[0], "rb") as tmd:
    tmd.seek(0x18C)
    title_id = tmd.read(0x8)
    tmd.seek(0x1DE)
    content_count = struct.unpack(">H", tmd.read(0x2))[0]
    tmd.seek(0x204)
    tmd_index = tmd.read(0x2)[::-1]
    for c in range(content_count):
        tmd.seek(0xB04 + (0x30 * c))
        content_id = binascii.hexlify(tmd.read(0x4)).decode('utf-8')
        tmd.seek(0xB08 + (0x30 * c))
        content_index = tmd.read(0x2)
        tmd.seek(0xB0A + (0x30 * c))
        content_type = struct.unpack(">H", tmd.read(0x2))[0]
        tmd.seek(0xB0C + (0x30 * c))
        content_size = struct.unpack(">Q", tmd.read(0x8))[0]
        # content_size = os.path.getsize(content_id)
        tmd.seek(0xB14 + (0x30 * c))
        content_hash = tmd.read(0x14)
        contents.append([content_id, content_index, content_type, content_size, content_hash])

print("Title ID:               " + binascii.hexlify(title_id).decode('utf-8').upper())

# find encrypted titlekey
encrypted_titlekey = b""
if os.path.isfile("title.tik"):
    with open("title.tik", "rb") as cetk:
        cetk.seek(0x1BF)
        encrypted_titlekey = cetk.read(0x10)
elif len(sys.argv) > 1:
    encrypted_titlekey = binascii.unhexlify(sys.argv[1])
else:
    sys.exit("Missing CETK (title.tik). Please add an argument containing the encrypted titlekey.")

print("Encrypted Titlekey:     " + binascii.hexlify(encrypted_titlekey).decode('utf-8').upper())

# decryption fun
cipher_titlekey = AES.new(ckey, AES.MODE_CBC, title_id + (b"\0" * 8))
decrypted_titlekey = cipher_titlekey.decrypt(encrypted_titlekey)
print("Decrypted Titlekey:     " + binascii.hexlify(decrypted_titlekey).decode('utf-8').upper())

for c in contents:
    print("Decrypting {}...".format(c[0]))
    left = os.path.getsize(c[0] + ".app")  # set to current size

    if c[2] & 0x2:  # if has a hash tree
        chunk_count = left // 0x10000
        chunk_num = 0
        with open(c[0] + ".h3", "rb") as h3:
            h3_hashes = h3.read()
        if SHA1.new(h3_hashes).digest() == c[4]:
            print("H3 Hash valid")
        else:
            print("H3 Hash mismatch!")
            print(" > TMD:    " + binascii.hexlify(c[4]).decode('utf-8').upper())
            print(" > Result: " + content_hash.hexdigest().upper())
        print("Chunks: {}".format(chunk_count))
        h0_hash_num = 0
        h1_hash_num = 0
        h2_hash_num = 0
        h3_hash_num = 0
        with open(c[0] + ".app", "rb") as encrypted:
            with open(c[0] + ".app.dec", "wb") as decrypted:
                for chunk_num in range(chunk_count):
                    show_chunk(chunk_num, chunk_count)
                    # decrypt and verify hash tree
                    cipher_hash_tree = AES.new(decrypted_titlekey, AES.MODE_CBC, (b"\0" * 16))
                    hash_tree = cipher_hash_tree.decrypt(encrypted.read(0x400))
                    h0_hashes = hash_tree[0:0x140]
                    h1_hashes = hash_tree[0x140:0x280]
                    h2_hashes = hash_tree[0x280:0x3c0]
                    h0_hash = h0_hashes[(h0_hash_num * 0x14):((h0_hash_num + 1) * 0x14)]
                    h1_hash = h1_hashes[(h1_hash_num * 0x14):((h1_hash_num + 1) * 0x14)]
                    h2_hash = h2_hashes[(h2_hash_num * 0x14):((h2_hash_num + 1) * 0x14)]
                    h3_hash = h3_hashes[(h3_hash_num * 0x14):((h3_hash_num + 1) * 0x14)]
                    if SHA1.new(h0_hashes).digest() != h1_hash:
                        print("\rH0 Hashes invalid in chunk {}".format(chunk_num))
                    if SHA1.new(h1_hashes).digest() != h2_hash:
                        print("\rH1 Hashes invalid in chunk {}".format(chunk_num))
                    if SHA1.new(h2_hashes).digest() != h3_hash:
                        print("\rH2 Hashes invalid in chunk {}".format(chunk_num))
                    # doesn't feel right, but only way for a long number I know of
                    iv = int.from_bytes(h0_hash, byteorder='big') // 0x100000000
                    #print("{:0>32X}".format(iv))
                    cipher_content = AES.new(decrypted_titlekey, AES.MODE_CBC, binascii.unhexlify("{:0>32X}".format(iv)))
                    decrypted_data = cipher_content.decrypt(encrypted.read(0xFC00))
                    if SHA1.new(decrypted_data).digest() != h0_hash:
                        print("\rData block hash invalid in chunk {}".format(chunk_num))
                    decrypted.write(hash_tree + decrypted_data)
                    h0_hash_num += 1
                    if h0_hash_num >= 16:
                        h0_hash_num = 0
                        h1_hash_num += 1
                    if h1_hash_num >= 16:
                        h1_hash_num = 0
                        h2_hash_num += 1
                    if h2_hash_num >= 16:
                        h2_hash_num = 0
                        h3_hash_num += 1
                print("")
    else:
        cipher_content = AES.new(decrypted_titlekey, AES.MODE_CBC, c[1] + (b"\0" * 14))
        content_hash = SHA1.new()
        with open(c[0] + ".app", "rb") as encrypted:
            with open(c[0] + ".app.dec", "wb") as decrypted:
                for __ in range(int(math.floor((c[3] / readsize)) + 1)):
                    to_read = min(readsize, left)
                    encrypted_content = encrypted.read(to_read)
                    decrypted_content = cipher_content.decrypt(encrypted_content)
                    if not c[2] & 0x2:
                        content_hash.update(decrypted_content)
                    decrypted.write(decrypted_content)
                    left -= readsize
                    show_progress(c[3] - left, c[3])
                    if left <= 0:
                        print("")
                        break
        if c[4] == content_hash.digest():
            print("Content Hash valid")
        else:
            print("Content Hash mismatch!")
            print(" > TMD:    " + binascii.hexlify(c[4]).decode('utf-8').upper())
            print(" > Result: " + content_hash.hexdigest().upper())
