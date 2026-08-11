# FILE_MAP — GhostLock-X200 v1.3.0 file-by-file map

> Path → purpose → origin → license. README explains *how to use*; this file
> explains *what every file is*. Provenance terms: COPIED (verbatim upstream),
> DERIVED (modified from upstream), LOCAL (project-original).

## Root

| Path | Purpose | Origin | License |
|---|---|---|---|
| `README.md` | user-facing README (Chinese: overview + comparisons; details in docs/USAGE.zh-CN.md) | LOCAL | Apache-2.0 |
| `run_root.bat` | the single double-click entry: runs root.ps1, keeps window open (errors stay visible) | LOCAL | Apache-2.0 |
| `log/` | runtime log `ghostlock_root_<timestamp>.log` + panic diag bundle `ghostlock_diag_<timestamp>.zip` (auto-generated, not tracked) | LOCAL | Apache-2.0 |
| `release_notes_v1.3.0.md` | release changelog for v1.3.0 | LOCAL | Apache-2.0 |
| `docs/ARCHITECTURE.md` | architecture / STAGE flow / component map | LOCAL | Apache-2.0 |
| `docs/FILE_MAP.md` | this file | LOCAL | Apache-2.0 |
| `docs/USAGE.zh-CN.md` | detailed usage guide (Chinese): quick start, dependencies, params, FAQ | LOCAL | Apache-2.0 |
| `LICENSE` | Apache-2.0 license text (project-wide default) | LOCAL | Apache-2.0 |
| `NOTICE` | third-party notices + permissive_restore GPL note | LOCAL | Apache-2.0 |
| `THIRD_PARTY_NOTICES.md` | third-party code/reference inventory | LOCAL | Apache-2.0 |
| `SOURCE-URLS.md` | external/upstream sources with revisions | LOCAL | Apache-2.0 |
| `REUSE.toml` | SPDX/REUSE license metadata | LOCAL | Apache-2.0 |
| `.gitignore` / `.gitattributes` | repo hygiene / line-ending policy | LOCAL | — |

## exploit/ — device-side (NDK cross-compile → glt / w2host)

### exploit/src/ — local & derived sources

| Path | Purpose | Origin |
|---|---|---|
| `main.c` | glt main entry (trigger chain orchestration) | DERIVED |
| `slide.c` | W2 write-shape core exploit | DERIVED (local reimpl.) |
| `fops.c` | file_operations exploit | DERIVED |
| `util.c` | shared utility functions | DERIVED |
| `root.c` | root escalation | COPIED (IonStack) |
| `pipe.c` | pipe primitive | COPIED (IonStack) |
| `preload.c` | preload | COPIED (IonStack) |
| `su_daemon.c` | su daemon PIE (embedded into glt) | DERIVED |
| `standalone_main.c` | standalone entry (physscan builds) | DERIVED |
| `w2host.c` | cred leak + CAPSROOT + rootcmd socket; perf sampling idea from ghostlock-app / GhostLock-for-OnePlus (Apache-2.0), independent implementation (see file header) | LOCAL |
| `physscan.c` / `physscan_stub.c` | physical-memory scan tool (independent) | LOCAL |
| `common.h` | shared headers | DERIVED |
| `target_x200.h` | target config header (offsets_auto.py output shape) | DERIVED |
| `su_blob.S` / `wallpaper_blob.S` | embedded assembly blobs | COPIED |

### exploit/vendored/ — IonStack verbatim components

| Path | Purpose | Origin |
|---|---|---|
| `offset.h` | IonStack offset header | COPIED |
| `kernelsnitch/futex_hash.h` | futex hash helpers | COPIED |
| `kernelsnitch/timeutils.h` | timing helpers | COPIED |
| `kernelsnitch/utils.h` | utility macros | COPIED |
| `kernelsnitch/kernelsnitch.h` | kernelsnitch header (local build variant) | DERIVED |

### exploit/assets/ + exploit/build/

| Path | Purpose | Origin |
|---|---|---|
| `assets/wallpaper.webp` (+`.license`) | embedded wallpaper blob resource | COPIED |
| `build/build_glt_esync.sh` | self-contained NDK build for glt (glt-x200-b57-v1.0.elf) | LOCAL |
| `build/build_w2host.sh` | self-contained NDK build for w2host (w2host-x200-b57-v1.0) | LOCAL |

## modules/kernelsu/ — KernelSU kernel module (vendored)

| Path | Purpose | Origin | License |
|---|---|---|---|
| `kernelsu.ko` (+`.license`) | **shipped prebuilt module** (official KernelSU v3.2.5 release asset `android15-6.6_kernelsu.ko` + vermagic rewrite for X200 b57 via `patch_vermagic.py`; in-tree; vermagic matches b57) | UPSTREAM (official release + device adaptation) | GPL-2.0-only |
| `patch_vermagic.py` | reproducible device adaptation of the official ko (vermagic-only rewrite; input 5933ECA4 -> output 187BB1BD) | LOCAL (adaptation script) | GPL-2.0-only |
| (corresponding source) | official KernelSU v3.2.5 `kernel/` @ `b0bc817b4e966aa6aa830834eaf6ef765d821d40` (see SOURCE-URLS.md) | UPSTREAM | GPL-2.0-only |

## modules/permissive_restore/ — kernel module

| Path | Purpose | Origin | License |
|---|---|---|---|
| `permissive_restore.c` | delayed permissive-restore module (initialized=1 restore, GL-host zeroing, commit_creds, 25s enforcing=0) | LOCAL (original) | GPL-2.0-only |
| `Makefile` | Kbuild (`obj-m := permissive_restore.o`) | LOCAL | GPL-2.0-only |
| `build_permissive_restore.sh` | parameterized WSL build (KSRC/CC/LD) | LOCAL | GPL-2.0-only |
| `permissive_restore.ko` | **shipped prebuilt module** (source-built, in-tree) | LOCAL | GPL-2.0-only |

## tools/ — host-side (Windows/WSL)

### tools/scripts/ — one-shot orchestration

| Path | Purpose |
|---|---|
| `root.ps1` (repo root) | **one-click entry**: build detection → auto offset rebuild → runs main chain (GUI-guided) |
| `root_full_permissive_restore.ps1` | **main chain** STAGE1-7; `-WinOffsPath` / `-SkipPermissiveRestore` supported |
| `root_full_official.ps1` | legacy control chain (KSU only, enforcing stays) |
| `restart_w2.sh` | device-side helper (restart W2 host on target) |
| `find_adb.ps1` | smart adb locator (multi-location probing + `adb version` validation; shared by root.ps1 & main chain) |

### tools/offset_tools/ — offset toolchain

| Path | Purpose |
|---|---|
| `offsets_auto.py` | full offsets extractor (kallsyms + BTF + ELF → header/json) |
| `patch_ko_all.py` | ko symbol relocation (absolute addresses + `__versions` strip) |
| `rootcmd_client.py` | rootcmd socket client |
| `unpack_boot.py` | boot.img unpacking |
| `win_offs_b57.json` | b57 image-intrinsic offsets data |
| `requirements.txt` | pip dependencies (capstone, pyelftools) |

## refs/ + LICENSES/

| Path | Purpose |
|---|---|
| `LICENSES/Apache-2.0.txt` | SPDX license text |
| `LICENSES/GPL-2.0-only.txt` | SPDX license text |
