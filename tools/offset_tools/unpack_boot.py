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
    # header version 在 0x2C (0x28 是 os_version)
    ver = struct.unpack_from('<I', data, 0x2C)[0] & 0xFFFF
    print('header version:', ver)
    kernel_size = struct.unpack_from('<I', data, 0x08)[0]
    page_size = struct.unpack_from('<I', data, 0x24)[0]
    print('kernel_size:', hex(kernel_size), 'page_size:', page_size)
    if kernel_size == 0:
        print('no kernel in this image (kernel_size=0): likely init_boot/vendor_boot; use boot.img instead')
        return
    kernel_offset = _probe_kernel_offset(data, page_size)
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


def _probe_kernel_offset(data, page_size):
    """定位内核段偏移: 标准头用 page_size; 厂商头 page_size=0 (如 vivo 实为
    4K 页) 时探测常见页大小 / arm64 Image magic (0x38 处 ARMd) / 压缩魔数."""
    def looks(off):
        if off + 0x40 > len(data):
            return False
        seg = data[off:off + 0x40]
        if seg[0x38:0x3C] == b'ARMd':
            return True
        return seg[:2] == b'\x1f\x8b' or seg[:4] == b'\x02\x21\x4c\x18' \
            or seg[:6] == b'\xfd7zXZ\x00'
    if 0 < page_size < len(data) and looks(page_size):
        return page_size
    for ps in (2048, 4096, 8192, 16384):
        if looks(ps):
            return ps
    # 搜索压缩魔数 (b"ARMd" 在 Image 0x38, 先搜魔数更可靠)
    for sig in (b'\x02\x21\x4c\x18', b'\xfd7zXZ\x00', b'\x1f\x8b'):
        j = data.find(sig)
        if j >= 0 and j + 0x40 <= len(data):
            return j
    i = data.find(b'ARMd')
    if i >= 0x38 and i - 0x38 + 0x40 <= len(data):
        return i - 0x38
    return page_size if 0 < page_size < len(data) else 0

if __name__ == '__main__':
    unpack(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'out')
