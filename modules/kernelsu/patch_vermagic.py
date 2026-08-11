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
  # adapt for the device (默认 b57 release):
  python patch_vermagic.py android15-6.6_kernelsu.ko kernelsu.ko
  # 指定目标内核 release (完整 UTS_RELEASE, 取设备 /proc/version 第 3 字段):
  python patch_vermagic.py src.ko dst.ko \
    --release 6.6.89-android15-8-gb57af212129c-abogki457297774-4k
  # 输入不是官方 v3.2.5 资产时 (如自编译 ko / 已 patch 过的 ko):
  python patch_vermagic.py modules/kernelsu/kernelsu.ko out.ko --no-sha-check
  # 幂等: 输入已是目标 vermagic 时直接成功, 不报错.
  # 注意: 只改 vermagic 字符串, 不保证 ABI; modversions CRC 仍按编译时内核,
  #   非同构建内核 insmod 可能报 Unknown symbol/version (需重新编译).
"""

import hashlib
import os
import shutil
import struct
import sys

DEFAULT_RELEASE = "6.6.89-android15-8-gb57af212129c-abogki457297774-4k"
OLD_VERMAGIC = (
    b"6.6.127-4k-g46a034eca005-dirty SMP preempt mod_unload modversions aarch64"
)
MODULE_FLAGS = " SMP preempt mod_unload modversions aarch64"
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


def read_vermagic(data, mi_off, mi_size):
    """返回当前 vermagic 字节 (不含 'vermagic=' 前缀)."""
    mi = bytes(data[mi_off : mi_off + mi_size])
    pos = mi.find(b"vermagic=")
    if pos < 0:
        return None, None
    end = mi.find(b"\x00", pos)
    if end < 0:
        end = mi_size
    return mi[pos + 9 : end], mi_size - (pos + 9)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    src, dst = sys.argv[1], sys.argv[2]
    release = DEFAULT_RELEASE
    no_sha = False
    rest = sys.argv[3:]
    if "--release" in rest:
        release = rest[rest.index("--release") + 1]
    if "--no-sha-check" in rest:
        no_sha = True
    if not release:
        raise RuntimeError("--release 不能为空")
    new_vermagic = (release + MODULE_FLAGS).encode()

    data = bytearray(open(src, "rb").read())
    h = hashlib.sha256(bytes(data)).hexdigest().upper()
    if not no_sha and h != INPUT_SHA256:
        print("WARNING: input SHA256 is %s (expected %s)" % (h, INPUT_SHA256))
        print("This is not the official v3.2.5 android15-6.6 asset; aborting.")
        print("(自编译/已适配的 ko 请加 --no-sha-check)")
        sys.exit(1)

    mi_off, mi_size = find_modinfo(data)
    cur, space = read_vermagic(data, mi_off, mi_size)
    if cur is None:
        raise RuntimeError(".modinfo 中未找到 vermagic=")
    if cur == new_vermagic:
        print("OK: 输入已是目标 vermagic, 无需修改 (幂等)")
        if os.path.abspath(src) != os.path.abspath(dst):
            shutil.copyfile(src, dst)
            print("已复制:", dst)
        print("VERIFY:", (b"vermagic=" + cur).decode(errors="replace"))
        return 0

    # 覆盖式改写: 新 vermagic 不得越出 .modinfo 段
    if len(new_vermagic) > space:
        raise RuntimeError(
            "新 vermagic 长度 %d > 现有空间 %d; 该 ko 不宜直接改写, 需用官方资产重新 patch"
            % (len(new_vermagic), space))
    # 定位实际写入起点 (read_vermagic 已知 vermagic= 起始)
    mi2 = bytes(data[mi_off : mi_off + mi_size])
    pos = mi2.find(b"vermagic=")
    data[mi_off + pos + 9 : mi_off + pos + 9 + len(new_vermagic)] = new_vermagic
    data[mi_off + pos + 9 + len(new_vermagic)] = 0  # '\0' terminator
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
