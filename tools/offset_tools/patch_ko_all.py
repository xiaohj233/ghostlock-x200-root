# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
import sys, struct, shutil
from elftools.elf.elffile import ELFFile
# usage: patch_ko_all.py <src.ko> <kallsyms> <dst.ko> [allow_keep_names]
SRC = sys.argv[1]; KALLS = sys.argv[2]; DST = sys.argv[3]
keep_ok = set()
if len(sys.argv) > 4:
    keep_ok = set(sys.argv[4].split(','))

syms = {}
for line in open(KALLS, errors="replace"):
    p = line.split()
    if len(p) >= 3:
        try:
            a = int(p[0], 16)
        except ValueError:
            continue
        if a != 0 and p[2] not in syms:
            syms[p[2]] = a

shutil.copy(SRC, DST)
with open(DST, "r+b") as f:
    elf = ELFFile(f)
    hdr = elf.header
    shoff_base = hdr["e_shoff"]; shnum = hdr["e_shnum"]; shentsize = hdr["e_shentsize"]
    # shstrtab 名字解析
    shstrndx = hdr["e_shstrndx"]
    f.seek(shoff_base + shstrndx * shentsize)
    sh = f.read(shentsize)
    strtab_off = struct.unpack("<Q", sh[0x18:0x20])[0]
    strtab_size = struct.unpack("<Q", sh[0x20:0x28])[0]
    f.seek(strtab_off)
    st_data = f.read(strtab_size)
    def sec_name(idx):
        f.seek(shoff_base + idx * shentsize)
        sh = f.read(shentsize)
        nmoff = struct.unpack("<I", sh[0:4])[0]
        e = st_data.find(b"\x00", nmoff)
        return st_data[nmoff:e].decode(errors="replace")

    # 1) 符号重定位
    symtab = elf.get_section_by_name(".symtab")
    entsize = symtab["sh_entsize"]; count = symtab["sh_size"] // entsize
    strtab = elf.get_section(symtab["sh_link"]); strdata = strtab.data()
    patched = 0; missing = []; kept = []
    for i in range(count):
        f.seek(symtab["sh_offset"] + i * entsize)
        raw = f.read(entsize)
        st_name = struct.unpack("<I", raw[0:4])[0]
        st_shndx = struct.unpack("<H", raw[6:8])[0]
        if st_shndx != 0:
            continue
        name = strdata[st_name:strdata.find(b"\x00", st_name)].decode(errors="replace")
        if not name:
            continue
        if name in keep_ok:
            kept.append(name)
            continue
        if name in syms:
            f.seek(symtab["sh_offset"] + i * entsize + 8)
            f.write(struct.pack("<Q", syms[name]))
            f.seek(symtab["sh_offset"] + i * entsize + 6)
            f.write(struct.pack("<H", 0xFFF1))
            patched += 1
        else:
            missing.append(name)

    # 2) 清空 __versions 段 (sh_size=0): 本地 CRC=0 表与真机不匹配会被拒
    for idx in range(shnum):
        if sec_name(idx) == "__versions":
            f.seek(shoff_base + idx * shentsize + 0x20)
            f.write(struct.pack("<Q", 0))
            print("versions: stripped (sec %d sh_size=0)" % idx)
            break
    else:
        print("versions: section not found")

    print("patched:", patched, "kept:", kept)
    print("MISSING:", sorted(missing)[:40], "count=", len(missing))