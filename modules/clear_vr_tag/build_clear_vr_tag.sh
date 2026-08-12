#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Build clear_vr_tag.ko for the GhostLock-X200 chain (vivo X200 b57).
# vr.ko anti-root countermeasure: kretprobe on commit_creds clears the
# per-task vr tags (task+0x06/0x2c) and TIF_SYSCALL_TRACEPOINT (0x400) for
# real non-root->root escalations, so vr.ko's sys_exit kill never fires.
#
# Requirements / usage: same as build_permissive_restore.sh
#   bash build_clear_vr_tag.sh -k /path/to/b57-kernel-tree
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR"
KSRC=""
CC="clang"
LD="ld.lld"

while [ $# -gt 0 ]; do
  case "$1" in
    -s) SRC="$2"; shift 2 ;;
    -k) KSRC="$2"; shift 2 ;;
    -c) CC="$2"; shift 2 ;;
    -l) LD="$2"; shift 2 ;;
    *) echo "usage: $0 [-s <srcdir>] [-k <ksrc>] [-c <clang>] [-l <ld>]" >&2; exit 2 ;;
  esac
done
if [ -z "$KSRC" ] && [ -n "$KSRC_ENV" ]; then KSRC="$KSRC_ENV"; fi
if [ -z "$KSRC" ] || [ ! -d "$KSRC" ]; then echo "ERR: kernel source tree required (-k)" >&2; exit 1; fi
command -v "$CC" >/dev/null 2>&1 || { echo "ERR: $CC not found" >&2; exit 1; }
command -v "$LD" >/dev/null 2>&1 || { echo "ERR: $LD not found" >&2; exit 1; }

cd "$KSRC"
make ARCH=arm64 CC="$CC" LD="$LD" KCFLAGS="-Wno-default-const-init-var-unsafe" M="$SRC" modules
echo "OK: $SRC/clear_vr_tag.ko ($(stat -c%s "$SRC/clear_vr_tag.ko") bytes)"
echo "NOTE: repatch with tools/offset_tools/patch_ko_all.py against current boot kallsyms before INSMOD"
