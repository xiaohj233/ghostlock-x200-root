#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 2026 GhostLock-X200 contributors
"""
patch_vermagic.py - official KernelSU v3.2.5 module device adaptation
(rewrites only the vermagic string; no functional change).

Source chain (fully reproducible):
  1. Official asset: KernelSU v3.2.5 release
     https://github.com/tiann/KernelSU/releases/download/v3.2.5/android15-6.6_kernelsu.ko
       SHA256  = 5933ECA4EC82DACFF4209745DD7228CF95352AEF7423BA7434F8542BC848AA8C
       BuildID = b61aef7e3fae7d02afb759c7a4acdecdd07aea2e
       license = GPL-2.0-only; corresponding source = official kernel/ sources
                 @ b0bc817b4e966aa6aa830834eaf6ef765d821d40 (tiann/KernelSU)
       vermagic= 6.6.127-4k-g46a034eca005-dirty (GKI 6.6.127; fails the loader
                 check on the X200 b57 kernel)
  2. This script: rewrites the .modinfo vermagic string to the target device
     kernel value and appends a '\\0' terminator. It touches no code, symbol
     or section layout; the BuildID is unchanged (byte-level same origin is
     verifiable) and the module behaviour is unchanged.
  3. Output: SHA256 = 187BB1BD4732DD1E193C09E1BA35A5D3A2B35190B32AABF3F2F7B0CDB03A71FB
     (= modules/kernelsu/kernelsu.ko; device-verified INSMOD on X200 b57).

Build record: 2026-08-09 development log (session
019fcfc8-53d7-7e90-8301-1b8f314179b9). Reproduction is self-verified below.

Usage:
  # download the official asset:
  curl -L -o android15-6.6_kernelsu.ko \
    https://github.com/tiann/KernelSU/releases/download/v3.2.5/android15-6.6_kernelsu.ko
  # adapt for the device:
  python patch_vermagic.py android15-6.6_kernelsu.ko kernelsu.ko
  # output SHA256 must equal 187BB1BD...
"""

import hashlib
import struct
import sys

OLD_VERMAGIC = (
    b"6.6.127-4k-g46a034eca005-dirty SMP preempt mod_unload modversions aarch64"
)
NEW_VERMAGIC = (
    b"6.6.89-android15-8-gb57af212129c-abogki457297774-4k "
    b"SMP preempt mod_unload modversions aarch64"
)
INPUT_SHA256 = "5933ECA4EC82DACFF4209745DD7228CF95352AEF7423BA7434F8542BC848AA8C"
EXPECTED_SHA256 = "187BB1BD4732DD1E193C09E1BA35A5D3A2B35190B32AABF3F2F7B0CDB03A71FB"


def find_modinfo(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sh = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<Q", data, sh + 0x18)[0]
    shstr_size = struct.unpack_from("<Q", data, sh + 0x20)[0]
    shstr = bytes(data[shstr_off : shstr_off + shstr_size])
    for k in range(e_shnum):
        shk = e_shoff + k * e_shentsize
        name_off = struct.unpack_from("<I", data, shk)[0]
        name = shstr[name_off : shstr.find(b"\x00", name_off)].decode(
            errors="replace"
        )
        if name == ".modinfo":
            mi_off = struct.unpack_from("<Q", data, shk + 0x18)[0]
            mi_size = struct.unpack_from("<Q", data, shk + 0x20)[0]
            return mi_off, mi_size
    raise RuntimeError(".modinfo section not found")


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    src, dst = sys.argv[1], sys.argv[2]

    data = bytearray(open(src, "rb").read())
    h = hashlib.sha256(bytes(data)).hexdigest().upper()
    if h != INPUT_SHA256:
        print("WARNING: input SHA256 is %s (expected %s)" % (h, INPUT_SHA256))
        print("This is not the official v3.2.5 android15-6.6 asset; aborting.")
        sys.exit(1)

    mi_off, mi_size = find_modinfo(data)
    mi = bytes(data[mi_off : mi_off + mi_size])
    pos = mi.find(b"vermagic=" + OLD_VERMAGIC)
    if pos < 0:
        raise RuntimeError("old vermagic not found; input already patched?")
    end = mi_off + pos + 9 + len(NEW_VERMAGIC)
    assert end < mi_off + mi_size, "vermagic rewrite would overflow .modinfo"
    data[mi_off + pos + 9 : mi_off + pos + 9 + len(NEW_VERMAGIC)] = NEW_VERMAGIC
    data[mi_off + pos + 9 + len(NEW_VERMAGIC)] = 0  # '\0' terminator
    open(dst, "wb").write(bytes(data))

    out = open(dst, "rb").read()
    h2 = hashlib.sha256(out).hexdigest().upper()
    print("output SHA256:", h2)
    if h2 == EXPECTED_SHA256:
        print("OK: output matches modules/kernelsu/kernelsu.ko (187BB1BD...)")
    else:
        print("WARNING: output differs from the shipped 187BB1BD build.")
    mi2 = out[mi_off : mi_off + mi_size]
    for kv in mi2.split(b"\x00"):
        if kv.startswith(b"vermagic="):
            print("VERIFY:", kv.decode(errors="replace"))
    return 0 if h2 == EXPECTED_SHA256 else 1


if __name__ == "__main__":
    sys.exit(main())
