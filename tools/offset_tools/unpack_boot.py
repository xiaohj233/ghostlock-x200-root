#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
"""Minimal Android boot image unpacker (header v2/v3/v4) + kernel decompression.
Usage: python3 unpack_boot.py boot.img [outdir]
"""
import struct, sys, os, subprocess, tempfile

def unpack(path, outdir):
    os.makedirs(outdir, exist_ok=True)
    data = open(path, 'rb').read()
    if data[:8] != b'ANDROID!':
        print('not an android boot image')
        return
    # header v2
    ver = struct.unpack_from('<I', data, 0x28)[0] & 0xFFFF
    print('header version:', ver)
    kernel_size = struct.unpack_from('<I', data, 0x08)[0]
    page_size = struct.unpack_from('<I', data, 0x24)[0]
    print('kernel_size:', hex(kernel_size), 'page_size:', page_size)
    if kernel_size == 0:
        print('no kernel in this image (kernel_size=0): likely init_boot/vendor_boot; use boot.img instead')
        return
    if ver <= 2:
        kernel_offset = page_size
    else:
        # v3/v4: header is one page, kernel follows immediately
        kernel_offset = page_size
    kernel = data[kernel_offset:kernel_offset + kernel_size]
    open(os.path.join(outdir, 'kernel.raw'), 'wb').write(kernel)
    print('kernel.raw written:', len(kernel), 'bytes')
    # try decompress
    for algo, cmd in [('gzip', ['gzip', '-d']), ('lz4', ['lz4', '-d']), ('xz', ['xz', '-d'])]:
        if kernel[:2] == b'\x1f\x8b' or kernel[:4] == b'\x02\x21\x4c\x18' or kernel[:6] == b'\xfd7zXZ\x00':
            print('detected:', algo)
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.in') as f:
                    f.write(kernel)
                    tmpin = f.name
                tmpout = tmpin + '.out'
                subprocess.run(cmd + ['-c', tmpin], stdout=open(tmpout, 'wb'), check=True)
                img = open(tmpout, 'rb').read()
                open(os.path.join(outdir, 'Image'), 'wb').write(img)
                print('Image written:', len(img), 'bytes')
                os.unlink(tmpin); os.unlink(tmpout)
                break
            except Exception as e:
                print(algo, 'failed:', e)
    else:
        print('no known compression (raw Image?)')

if __name__ == '__main__':
    unpack(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'out')
