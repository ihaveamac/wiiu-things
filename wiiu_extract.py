#!/usr/bin/env python3

# fst parser by ihaveamac, with assistance from MarcusD

import binascii
import os
import struct
import sys


def read_int(f, s):
    return int.from_bytes(f.read(s), byteorder='big')


def read_string(f):
    buf = b''
    while True:
        char = f.read(1)
        if char == b'\0' or char == b'':
            return buf.decode('utf-8')
        buf += char


def file_chunk_offset(offset):
    chunks = (offset // 0xFC00)
    single_chunk_offset = offset % 0xFC00
    actual_offset = single_chunk_offset + ((chunks + 1) * 0x400) + (chunks * 0xFC00)
    return actual_offset


def iterate_directory(f, iter_start, count, names_offset, depth, topdir, content_records, can_extract, tree=[]):
    i = iter_start

    while i < count:
        f_type = ord(f.read(1))
        isdir = f_type & 1

        name_offset = read_int(f, 3) + names_offset
        orig_offset = f.tell()
        f.seek(name_offset)
        f_name = read_string(f)
        f.seek(orig_offset)

        f_offset = read_int(f, 4)
        f_size = read_int(f, 4)
        f_flags = read_int(f, 2)
        if f_flags & 4:
            f_offset <<= 5

        if not isdir and not f_flags & 4:
            f_offset *= 0x20

        content_index = read_int(f, 2)

        # this should be based on f_flags, but I'm not sure if there is a reliable way to determine this yet.
        has_hash_tree = contents[content_index][2] & 2
        f_real_offset = file_chunk_offset(f_offset) if has_hash_tree else f_offset

        # to_print = '{:05} ({:02X}) '.format(i, f_type) + ('  ' * depth) + ('* ' if isdir else '- ') + f_name
        # if not isdir:
        #     to_print += ' (offs=0x{:X} realoffs=0x{:X} size=0x{:X})'.format(f_offset, file_chunk_offset(f_offset), f_size)
        # to_print += ' (flags=0x{:X}) (cindex=0x{:04X}) (cid=0x{})'.format(f_flags, content_index, content_records[content_index][0].upper())
        to_print = ''
        if '--dump-info' in sys.argv:
            to_print += '{:05} type={:02X} flags={:03X} offs={:010X} realoffs={:010X} size={:07X} cindex={:04X} cid={} '.format(i, f_type, f_flags, f_offset, f_real_offset, f_size, content_index, content_records[content_index][0].upper())
        if '--full-paths' in sys.argv:
            to_print += ''.join(tree) + f_name
        else:
            to_print += ('  ' * depth) + ('* ' if isdir else '- ') + f_name
        if not (f_type & 0x80) or '--all' in sys.argv:
            print(to_print + (' (deleted)' if f_type & 0x80 else ''))

        if isdir:
            if f_offset <= topdir:
                return
            tree.append(f_name + '/')
            os.makedirs(''.join(tree), exist_ok=True)
            iterate_directory(f, i + 1, f_size, names_offset, depth + 1, f_offset, content_records, can_extract, tree=tree)
            del tree[-1]
            i = f_size - 1
        elif can_extract and '--no-extract' not in sys.argv:
            # why nintendo?
            with open(content_records[content_index][0] + '.app.dec', 'rb') as c:
                with open(''.join(tree) + f_name, 'wb') as o:
                    c.seek(f_real_offset)
                    buf = b''
                    left = f_size
                    while left > 0:
                        to_read = min(0x20, left)
                        buf += c.read(to_read)
                        left -= to_read
                        if len(buf) >= 0x200:
                            o.write(buf)
                            buf = b''
                        if has_hash_tree and c.tell() % 0x10000 < 0x400:
                            c.seek(0x400, 1)
                    o.write(buf)

        i += 1


if not os.path.isfile('title.tmd'):
    sys.exit('No TMD (title.tmd) was found.')

with open('title.tmd', 'rb') as f:
    # find title id and content id
    contents = []
    content_count = 0

    f.seek(0x1DE)
    content_count = struct.unpack('>H', f.read(0x2))[0]

    f.seek(0x204)
    tmd_index = f.read(0x2)[::-1]

    for c in range(content_count):
        f.seek(0xB04 + (0x30 * c))
        content_id = f.read(0x4).hex()

        f.seek(0xB08 + (0x30 * c))
        content_index = f.read(0x2).hex()

        f.seek(0xB0A + (0x30 * c))
        content_type = struct.unpack('>H', f.read(0x2))[0]

        contents.append([content_id, content_index, content_type])

    fst_header_filename = contents[0][0] + '.app.dec'
    print('FST header file: ' + fst_header_filename)
    # maybe i should add decryption here...
    if not os.path.isfile(fst_header_filename):
        sys.exit('Couldn\'t find FST header file, run wiiu_decrypt.py and try again.')
    can_extract = True
    for content in contents[1:]:
        if not os.path.isfile(content[0] + '.app.dec'):
            print('Couldn\'t find ' + content[0] + '.app.dec, extraction will be disabled.')
            can_extract = False
    with open(fst_header_filename, 'rb') as s:
        s.seek(4)
        exh_size = read_int(s, 4)
        exh_count = read_int(s, 4)

        print('exheader size: 0x{:X}'.format(exh_size))
        print('exheader count: {}'.format(exh_count))

        if exh_size == 0x20:
            s.seek(0x14, 1)

            for i in range(exh_count):
                print('#{0} ({0:X})'.format(i))
                print('- Unknown1: 0x' + s.read(4).hex())
                print('- Unknown2: 0x' + s.read(4).hex())
                print('- TitleID:  0x' + s.read(8).hex())
                print('- GroupID:  0x' + s.read(4).hex())
                print('- Flags?:   0x' + s.read(2).hex())
                print('')
                s.seek(0xA, 1)

            # what is this again?
            fsestart = s.tell()
            s.seek(8, 1)
            total_entries = read_int(s, 4)
            s.seek(4, 1)
            names_offset = fsestart + (total_entries * 0x10)

            iterate_directory(s, 1, total_entries, names_offset, 0, -1, contents, can_extract)

        else:
            sys.exit('invalid exheader size: 0x{:X}'.format(exh_size))
