#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
#
# extract_vr_offsets.py - 从 vivo vr.ko 自动提取反 root 对抗偏移
#
# 背景: vivo vr.ko 通过 android_rvh_commit_creds tracepoint 给"提权进程"
# 打标记 (task+0x06 / task+0x2c) 并在 syscall_trace_exit 的 inline hook 里
# 检测 euid==0 + 标记 -> do_exit 杀进程. 我们的 clear_vr_tag.ko 需要这些
# 偏移 (VR_TAG_A/B, thread_info 0x400 位) 才能精准清标记.
#
# 用法:
#   python3 extract_vr_offsets.py <vr.ko> [-o offsets.json]
#   (可选 -o: 输出 JSON, 默认打印)
#
# 分析原理:
#   1. 反汇编 (aarch64 objdump) 找 __tracepoint_android_rvh_commit_creds 的
#      android_rvh_probe_register 调用 -> 回调 handler 地址.
#   2. 反汇编 handler: 找 `mov w8,#0x400; stset x8,[xN]` (syscall tracepoint
#      标志位) 与 `strb w8,[xN,#A]; strb w8,[xN,#B]` 成对写 (标记 A/B).
#   3. 输出: {task_flags_off, tp_flag, tag_a_off, tag_b_off}.
import json
import re
import subprocess
import sys


def disassemble(ko_path):
    try:
        out = subprocess.run(
            ["aarch64-linux-gnu-objdump", "-d", ko_path],
            capture_output=True, text=True, check=True,
        ).stdout
    except FileNotFoundError:
        sys.exit("ERR: aarch64-linux-gnu-objdump not found (install cross binutils)")
    except subprocess.CalledProcessError as e:
        sys.exit(f"ERR: objdump failed: {e}")
    return out.splitlines()


def find_reg(s):
    m = re.search(r"\[x(\d+)\]", s)
    return f"x{m.group(1)}" if m else None


def analyze_capstone(ko_path):
    """capstone 后端 (objdump 缺失时回退, Windows 可直接跑, 无需 WSL).
    特征扫描 .text: `mov wX,#0x400` + `stset xX,[xR]` (TIF 标记位) 与其附近
    同基址的 strb 成对偏移 (vr tag A/B). 不依赖符号表/重定位. 返回 dict 或 None."""
    try:
        from elftools.elf.elffile import ELFFile
        import capstone
    except ImportError:
        sys.exit("ERR: 需要 pyelftools + capstone (pip install -r requirements.txt) "
                 "或 aarch64-linux-gnu-objdump")
    with open(ko_path, "rb") as f:
        elf = ELFFile(f)
        text = None
        base = 0
        for sec in elf.iter_sections():
            if sec.name == ".text":
                text = sec.data()
                base = sec["sh_addr"]
                break
    if text is None:
        sys.exit("ERR: ELF 中无 .text section")
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False
    # 内核由新 ISA 扩展 (LSE2/MOPS 等) 编译, capstone 5 可能无法解码个别指令,
    # 开启 skipdata 跳过未知指令继续, 避免 disasm 提前停止.
    md.skipdata = True
    insns = list(md.disasm(text, base))
    result = {"source": ko_path, "handler_va": None, "task_flags_off": 0,
              "tp_flag": None, "tag_a_off": None, "tag_b_off": None,
              "task_base_reg": None, "backend": "capstone"}
    for i, ins in enumerate(insns):
        if ins.mnemonic != "stset":
            continue
        # 前 10 条找 `mov wX,#0x400`
        for j in range(max(0, i - 10), i):
            p = insns[j]
            if p.mnemonic == "mov" and "0x400" in p.op_str:
                m = re.search(r"\[x(\d+)\]", ins.op_str)
                if not m:
                    continue
                base_reg = "x" + m.group(1)
                result["tp_flag"] = 0x400
                result["task_base_reg"] = base_reg
                tags = []
                for k in range(max(0, i - 60), min(len(insns), i + 60)):
                    s = insns[k]
                    if s.mnemonic == "strb":
                        # capstone 5: 寄存器可能是 wzr, 偏移可能是 #0x2c 十六进制
                        m2 = re.match(r"w(zr|\d+),\s*\[x(\d+),\s*#(0x[0-9a-f]+|\d+)\]",
                                      s.op_str)
                        if m2 and m2.group(2) == base_reg[1:]:
                            off = int(m2.group(3), 0)
                            if off not in tags:
                                tags.append(off)
                tags.sort()
                small = [o for o in tags if o <= 0x40]
                if len(small) >= 2:
                    result["tag_a_off"], result["tag_b_off"] = small[0], small[1]
                break
        if result["tag_a_off"] is not None and result["tag_b_off"] is not None:
            break
    if result["tag_a_off"] is None or result["tag_b_off"] is None:
        return None
    return result


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    ko = sys.argv[1]
    out_json = None
    if "-o" in sys.argv:
        out_json = sys.argv[sys.argv.index("-o") + 1]
    try:
        lines = disassemble(ko)
        backend = "objdump"
    except SystemExit:
        # objdump 缺失 -> capstone 后端 (Windows 免 WSL)
        res = analyze_capstone(ko)
        if res is None:
            sys.exit("ERR: capstone 特征扫描未命中 (0x400 stset + strb 对), "
                     "请人工检查 vr.ko 反汇编")
        print(f"[*] (capstone 后端) tp_flag=0x{res['tp_flag']:x} "
              f"tag_a={res['tag_a_off']} tag_b={res['tag_b_off']}")
        print(json.dumps({k: v for k, v in res.items() if k != "backend"}, indent=2))
        if out_json:
            with open(out_json, "w", encoding="utf-8") as f:
                json.dump({k: v for k, v in res.items() if k != "backend"}, f, indent=2)
            print(f"[*] written {out_json}")
        return

    # 1) locate the commit_creds tracepoint registration: adrp x0,
    #    __tracepoint_android_rvh_commit_creds -> android_rvh_probe_register
    handler = None
    for i, l in enumerate(lines):
        if "adrp" in l and "__tracepoint_android_rvh_commit_creds" in l:
            # next few instructions load x1 = handler (relocatable ELF shows
            # the resolved symbol as `<init_module+0x60>` / `<.text+0x64>`)
            for j in range(i, min(i + 8, len(lines))):
                s = lines[j]
                m = re.search(r"<init_module\+0x([0-9a-f]+)>", s)
                if m:
                    handler = int(m.group(1), 16)
                    break
                m = re.search(r"<\.text\+0x([0-9a-f]+)>", s)
                if m:
                    handler = int(m.group(1), 16)
                    break
            break
    if handler is None:
        sys.exit("ERR: commit_creds tracepoint handler not found")
    print(f"[*] commit_creds handler @ 0x{handler:x}")

    # 2) disassemble handler body: collect (instruction, offset) triples
    #    addr:   instr
    body = []
    in_fn = False
    for l in lines:
        m = re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+.*)", l)
        if not m:
            if in_fn:
                break
            continue
        addr = int(m.group(1), 16)
        text = m.group(3)
        if addr == handler:
            in_fn = True
        if in_fn:
            body.append((addr, text))
            if "ret" in text and addr > handler + 8:
                # keep scanning a little; handler may be short
                pass

    # find tag A/B write pair: strb wX,[xN,#A] and strb wX,[xN,#B] with
    # different offsets, plus the 0x400 stset on [xN] (task base)
    tag_a = tag_b = None
    tp_flag = None
    task_base_reg = None
    for addr, text in body:
        m = re.match(r"stset\s+x\d+,\s+\[x(\d+)\]", text)
        if m and not tp_flag:
            # look backwards for mov w8,#0x400
            for a2, t2 in body:
                if a2 < addr and "0x400" in t2 and "mov" in t2:
                    tp_flag = 0x400
                    task_base_reg = f"x{m.group(1)}"
                    break
        m = re.match(r"strb\s+w(\d+),\s+\[x(\d+),\s*#(\d+)\]", text)
        if m:
            off = int(m.group(3))
            if off in (0x06, 6, 0x2c, 44):
                if off in (6, 0x06) and tag_a is None:
                    tag_a = off
                elif off in (44, 0x2c) and tag_b is None:
                    tag_b = off

    if tag_a is None or tag_b is None:
        # fallback: scan for any two strb with same base reg and distinct offs
        writes = {}
        for addr, text in body:
            m = re.match(r"strb\s+w\d+,\s+\[x(\d+),\s*#(\d+)\]", text)
            if m:
                writes.setdefault(m.group(1), set()).add(int(m.group(2)))
        for reg, offs in writes.items():
            small = [o for o in offs if o <= 0x40]
            if len(small) >= 2:
                small.sort()
                tag_a, tag_b = small[0], small[1]
                task_base_reg = f"x{reg}"
                break

    result = {
        "source": ko,
        "handler_va": hex(handler),
        "task_flags_off": 0,
        "tp_flag": tp_flag if tp_flag is not None else 0x400,
        "tag_a_off": tag_a,
        "tag_b_off": tag_b,
        "task_base_reg": task_base_reg,
    }
    if tag_a is None or tag_b is None:
        print("[!] WARN: tag offsets not fully resolved, review handler asm:")
        for addr, text in body[:40]:
            print(f"    {addr:04x}: {text}")
        sys.exit(1)

    print(json.dumps(result, indent=2))
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"[*] written {out_json}")


if __name__ == "__main__":
    main()
