#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 2026 GhostLock-X200 contributors
#
# Build permissive_restore.ko for the GhostLock-X200 chain.
#
# Requirements:
#   - a kernel source tree matching the target device kernel (the vivo b57
#     6.6.89 tree is NOT distributed with this repository; obtain your own),
#   - clang + ld.lld on PATH (or override with -c / -l).
#
# Usage:
#   bash build_permissive_restore.sh [-s <srcdir>] [-k <ksrc>] [-c <clang>] [-l <ld>]
#   bash build_permissive_restore.sh [<srcdir>]        # legacy positional form (srcdir)
# Example: bash build_permissive_restore.sh -k /path/to/b57-kernel-tree
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR"
KSRC=""
CC="clang"
LD="ld.lld"

# legacy positional [srcdir]
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then SRC="$1"; shift; fi
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
if [ -z "$KSRC" ]; then
  echo "ERR: no kernel source tree. Pass -k <ksrc> or set KSRC_ENV." >&2
  echo "     (example: ~/android-kernel - a b57 6.6.89 kernel tree)" >&2
  exit 1
fi
if [ ! -d "$KSRC" ]; then echo "ERR: $KSRC does not exist" >&2; exit 1; fi
command -v "$CC" >/dev/null 2>&1 || { echo "ERR: $CC not found on PATH" >&2; exit 1; }
command -v "$LD" >/dev/null 2>&1 || { echo "ERR: $LD not found on PATH" >&2; exit 1; }

# Generate a minimal Module.symvers when missing. The final artifact is
# repatched to absolute addresses by tools/offset_tools/patch_ko_all.py, so CRC values
# are not verified by insmod afterwards.
if [ ! -s "$KSRC/Module.symvers" ]; then
  echo "WARN: $KSRC/Module.symvers missing, generating minimal table"
  cat > "$KSRC/Module.symvers" <<'SYM'
0x00000000	commit_creds	vmlinux	EXPORT_SYMBOL
0x00000000	prepare_kernel_cred	vmlinux	EXPORT_SYMBOL
0x00000000	kthread_create_on_node	vmlinux	EXPORT_SYMBOL
0x00000000	kthread_stop	vmlinux	EXPORT_SYMBOL
0x00000000	kthread_should_stop	vmlinux	EXPORT_SYMBOL
0x00000000	schedule_timeout_interruptible	vmlinux	EXPORT_SYMBOL
0x00000000	wake_up_process	vmlinux	EXPORT_SYMBOL
0x00000000	init_task	vmlinux	EXPORT_SYMBOL
0x00000000	msleep	vmlinux	EXPORT_SYMBOL
0x00000000	_printk	vmlinux	EXPORT_SYMBOL
0x00000000	printk	vmlinux	EXPORT_SYMBOL
0x00000000	param_ops_ulong	vmlinux	EXPORT_SYMBOL
0x00000000	module_layout	vmlinux	EXPORT_SYMBOL
SYM
fi

cd "$KSRC"
make ARCH=arm64 CC="$CC" LD="$LD"   KCFLAGS="-Wno-default-const-init-var-unsafe" M="$SRC" modules
echo "OK: $SRC/permissive_restore.ko ($(stat -c%s "$SRC/permissive_restore.ko") bytes)"
echo "NOTE: repatch this ko with tools/offset_tools/patch_ko_all.py against the current boot kallsyms before INSMOD"
