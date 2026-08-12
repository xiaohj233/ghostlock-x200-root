#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
#
# extract_vr_from_img.py - 从 OTA 全量包 / vendor_boot.img 一键自动提取 vr.ko
#                         并分析反 root 对抗偏移, 输出 vr_offsets.json
#
# 背景: vivo X200 (PD2415) 的 vr.ko 存放在 vendor_boot.img 的 vendor ramdisk
# (LZ4 legacy 压缩的 cpio 归档, lib/modules/vr.ko). 我们的 clear_vr_tag.ko
# 需要该固件对应 vr.ko 的 tag_a_off/tag_b_off/tp_flag 才能精准清标记.
# 本脚本把整条链路固化为一条命令:
#
#   全量包(payload.bin) --payload-dumper-go--> vendor_boot.img
#       --本脚本(纯 python LZ4+cpio)--> vr.ko
#       --extract_vr_offsets.py--> vr_offsets.json
#
# 用法 (Windows, python3):
#   python extract_vr_from_img.py --img vendor_boot.img [-o vr_offsets.json] [--save-ko vr.ko]
#   python extract_vr_from_img.py --payload payload.bin [--pd payload-dumper-go.exe] [...]
#
# 输出:
#   vr_offsets.json - 主链 root_full_permissive_restore.ps1 STAGE6.5 会自动读取
#                     并覆盖默认偏移 (tag_a/tag_b/tp_flag), 无需重新编译模块.
import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

VNDRBOOT_MAGIC = b"VNDRBOOT"
LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
CPIO_NEWC_MAGIC = b"070701"


# ---------- LZ4 legacy 解压 (自包含, 无第三方依赖) ----------

def lz4_block_decompress(data):
    """解压单个 LZ4 block (token 序列, 无 frame 头). 支持重叠拷贝 (RLE)."""
    ip = 0
    out = bytearray()
    n = len(data)
    while ip < n:
        token = data[ip]
        ip += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                b = data[ip]
                ip += 1
                lit_len += b
                if b != 255:
                    break
        out += data[ip:ip + lit_len]
        ip += lit_len
        if ip >= n:
            break
        if ip + 2 > n:
            break
        offset = data[ip] | (data[ip + 1] << 8)
        ip += 2
        match_len = (token & 0x0F) + 4
        if match_len == 19:
            while True:
                b = data[ip]
                ip += 1
                match_len += b
                if b != 255:
                    break
        start = len(out) - offset
        if start < 0:
            raise ValueError("LZ4 invalid match offset")
        for _ in range(match_len):
            out.append(out[start])
            start += 1
    return bytes(out)


def lz4_legacy_decompress(data):
    """解压 LZ4 legacy frame (magic 0x184C2102 + 8MiB 块序列)."""
    if data[:4] != LZ4_LEGACY_MAGIC:
        raise ValueError("not an LZ4 legacy stream (magic mismatch)")
    out = bytearray()
    pos = 4
    n = len(data)
    while pos + 4 <= n:
        size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if size == 0 or pos + size > n:
            break
        out += lz4_block_decompress(data[pos:pos + size])
        pos += size
    return bytes(out)


# ---------- cpio newc 解析 (自包含) ----------

def cpio_extract(data, target):
    """从 cpio newc (070701) 归档提取 target 路径文件, 返回 bytes 或 None."""
    pos = 0
    n = len(data)
    while pos + 110 <= n:
        hdr = data[pos:pos + 110]
        if hdr[:6] != CPIO_NEWC_MAGIC:
            break
        # newc 头部: magic[6] + 13 个 8 字节十六进制字段 (ino..check)
        fields = [int(hdr[6 + i * 8:6 + (i + 1) * 8], 16) for i in range(13)]
        namesize = fields[11]
        filesize = fields[6]
        name = data[pos + 110:pos + 110 + namesize - 1].decode("utf-8", "replace")
        data_start = (pos + 110 + namesize + 3) & ~3
        if name == target:
            return data[data_start:data_start + filesize]
        pos = (data_start + filesize + 3) & ~3
        if name == "TRAILER!!!":
            break
    return None


# ---------- vendor_boot.img 解析 ----------

def parse_vndrboot(data):
    if data[:8] != VNDRBOOT_MAGIC:
        return None
    ver = struct.unpack_from("<I", data, 0x08)[0]
    page = struct.unpack_from("<I", data, 0x0C)[0]
    vrd_size = struct.unpack_from("<I", data, 0x18)[0]
    return {"ver": ver, "page": page, "vrd_size": vrd_size}


def find_lz4_legacy(data, start=0x1000):
    return data.find(LZ4_LEGACY_MAGIC, start)


def extract_vr_ko_from_vendor_boot(vb_path):
    """vendor_boot.img -> vr.ko bytes. 纯 python, 不依赖 lz4/cpio CLI."""
    with open(vb_path, "rb") as f:
        data = f.read()
    hdr = parse_vndrboot(data)
    if hdr is None:
        sys.exit(f"ERR: {vb_path} 不是 VNDRBOOT vendor_boot 镜像")
    off = find_lz4_legacy(data)
    if off is None or off < 0:
        sys.exit("ERR: vendor_boot 中未找到 LZ4 legacy magic (02 21 4c 18)")
    size = hdr["vrd_size"] if hdr["vrd_size"] else len(data) - off
    print(f"[*] vendor_boot hdr_ver={hdr['ver']} page={hdr['page']} "
          f"vramdisk_off=0x{off:x} size={size}")
    ramdisk = data[off:off + size]
    try:
        cpio = lz4_legacy_decompress(ramdisk)
    except ValueError as e:
        sys.exit(f"ERR: LZ4 legacy 解压失败: {e}")
    print(f"[*] vramdisk 解压 -> cpio {len(cpio)} bytes")
    vr = cpio_extract(cpio, "lib/modules/vr.ko")
    if vr is None:
        sys.exit("ERR: cpio 中未找到 lib/modules/vr.ko (可能路径不同, 需人工确认)")
    print(f"[*] vr.ko 提取成功: {len(vr)} bytes")
    return vr


# ---------- payload.bin 前置 (Windows 侧调 payload-dumper-go) ----------

def extract_vendor_boot_from_payload(payload, pd_exe, outdir):
    if not pd_exe or not os.path.exists(pd_exe):
        sys.exit("ERR: 未找到 payload-dumper-go.exe。请用 --pd 指定, 或先运行 root.ps1 "
                 "自动下载 (GitHub release: https://github.com/ssut/payload-dumper-go/releases)")
    os.makedirs(outdir, exist_ok=True)
    print(f"[*] payload-dumper-go: {pd_exe} -> vendor_boot")
    r = subprocess.run([pd_exe, "-partitions", "vendor_boot", "-o", outdir, payload],
                       capture_output=True, text=True)
    vb = os.path.join(outdir, "vendor_boot.img")
    if not os.path.exists(vb):
        sys.exit(f"ERR: payload 解包失败: {r.stderr[-500:]}")
    print(f"[*] vendor_boot.img: {os.path.getsize(vb)} bytes")
    return vb


def find_payload_dumper():
    """自动探测 payload-dumper-go.exe 常见位置 (与 root.ps1 deps 布局一致)."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pkg_root = os.path.abspath(os.path.join(script_dir, "..", ".."))
    candidates = [
        os.path.join(pkg_root, "payload-dumper-go", "payload-dumper-go.exe"),
        os.path.join(pkg_root, "payload-dumper-go.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     "GhostLock-X200", "deps", "payload-dumper-go", "payload-dumper-go.exe"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def main():
    ap = argparse.ArgumentParser(description="从 OTA 全量包/vendor_boot.img 自动提取 vr.ko 偏移")
    ap.add_argument("--img", help="vendor_boot.img 路径")
    ap.add_argument("--payload", help="OTA 全量包 payload.bin 路径 (需 --pd)")
    ap.add_argument("--pd", help="payload-dumper-go.exe 路径 (默认自动探测 deps 常见位置)")
    ap.add_argument("-o", "--out", default="vr_offsets.json", help="输出 vr_offsets.json 路径")
    ap.add_argument("--save-ko", help="额外保存 vr.ko 到指定路径")
    args = ap.parse_args()

    if args.payload:
        pd = args.pd or find_payload_dumper()
        vb = extract_vendor_boot_from_payload(
            args.payload, pd, os.path.dirname(args.out) or ".")
    elif args.img:
        vb = args.img
    else:
        sys.exit("用法: --img vendor_boot.img 或 --payload payload.bin --pd payload-dumper-go.exe")

    vr = extract_vr_ko_from_vendor_boot(vb)
    if args.save_ko:
        with open(args.save_ko, "wb") as f:
            f.write(vr)
        print(f"[*] vr.ko 已保存: {args.save_ko}")

    # 调 extract_vr_offsets.py 分析偏移 (需要 aarch64-linux-gnu-objdump):
    #   - Linux 直接跑
    #   - Windows 自动经 WSL kali-linux 执行 (跨 binutils 在 kali 侧)
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "extract_vr_offsets.py")
    with tempfile.NamedTemporaryFile(suffix=".ko", delete=False) as tf:
        tf.write(vr)
        ko_tmp = tf.name
    try:
        # 优先本地 python 直接跑 (extract_vr_offsets.py 自带 capstone 后端,
        # Windows 免 WSL); 失败时回退 WSL kali (objdump 后端)
        r = subprocess.run([sys.executable, script, ko_tmp, "-o", args.out],
                           capture_output=True, text=True)
        if r.returncode != 0 and sys.platform == "win32":
            # Windows 路径 -> WSL /mnt/<drive>/... 路径
            def to_wsl(p):
                p = p.replace(":", "").replace("\\", "/")
                return "/mnt/" + p[0].lower() + p[1:]
            cmd = ["wsl", "-d", "kali-linux", "--", "bash", "-lc",
                   "python3 {} {} -o {}".format(
                       to_wsl(script), to_wsl(ko_tmp),
                       to_wsl(os.path.abspath(args.out)))]
            r = subprocess.run(cmd, capture_output=True, text=True)
        print(r.stdout)
        if r.returncode != 0:
            print(r.stderr)
            sys.exit(f"ERR: extract_vr_offsets.py 失败 (rc={r.returncode})")
    finally:
        os.unlink(ko_tmp)

    with open(args.out, encoding="utf-8") as f:
        offs = json.load(f)
    print("[*] 完成. 主链 STAGE6.5 会自动读取本文件覆盖默认偏移并应用, 无需重编模块.")
    print(f"    tag_a_off={offs.get('tag_a_off')} tag_b_off={offs.get('tag_b_off')} "
          f"tp_flag={offs.get('tp_flag')}")


if __name__ == "__main__":
    main()
