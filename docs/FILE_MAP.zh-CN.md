<!--
SPDX-FileCopyrightText: 2026 GhostLock-X200 contributors
SPDX-License-Identifier: Apache-2.0
-->
# FILE_MAP — GhostLock-X200 v1.0 逐文件映射（中文版）

> 路径 → 用途 → 来源 → 许可证。README 说明*怎么用*；本文件说明*每个文件是什么*。来源术语：COPIED（上游逐字）、DERIVED（自上游修改）、LOCAL（项目原创）。

## 根目录

| 路径 | 用途 | 来源 | 许可证 |
|---|---|---|---|
| `README.md` | 用户文档（中文：概述 + 项目对比；详细用法见 docs/USAGE.zh-CN.md） | LOCAL | Apache-2.0 |
| `docs/ARCHITECTURE.md` | 架构 / STAGE 流程 / 组件映射 | LOCAL | Apache-2.0 |
| `docs/ARCHITECTURE.zh-CN.md` | 架构（中文版） | LOCAL | Apache-2.0 |
| `docs/FILE_MAP.md` | 本文件 | LOCAL | Apache-2.0 |
| `docs/FILE_MAP.zh-CN.md` | 本文件（中文版） | LOCAL | Apache-2.0 |
| `docs/USAGE.zh-CN.md` | 详细使用说明（中文）：快速开始、依赖、参数、FAQ | LOCAL | Apache-2.0 |
| `LICENSE` | Apache-2.0 许可证文本（项目默认） | LOCAL | Apache-2.0 |
| `NOTICE` | 第三方声明 + permissive_restore GPL 说明 | LOCAL | Apache-2.0 |
| `THIRD_PARTY_NOTICES.md` | 第三方代码/参考清单 | LOCAL | Apache-2.0 |
| `SOURCE-URLS.md` | 外部/上游来源及版本 | LOCAL | Apache-2.0 |
| `REUSE.toml` | SPDX/REUSE 许可证元数据 | LOCAL | Apache-2.0 |
| `.gitignore` / `.gitattributes` | 仓库卫生 / 行尾策略 | LOCAL | — |

## exploit/ — 设备端（NDK 交叉编译 → glt / w2host）

### exploit/src/ — 本地及衍生源码

| 路径 | 用途 | 来源 |
|---|---|---|
| `main.c` | glt 主入口（触发链编排） | DERIVED |
| `slide.c` | W2 写形态核心 exploit | DERIVED（本地重实现） |
| `fops.c` | file_operations exploit | DERIVED |
| `util.c` | 共享工具函数 | DERIVED |
| `root.c` | root 提权 | COPIED (IonStack) |
| `pipe.c` | pipe 原语 | COPIED (IonStack) |
| `preload.c` | 提权后 payload | COPIED (IonStack) |
| `su_daemon.c` | su daemon PIE（嵌入 glt） | DERIVED |
| `standalone_main.c` | 独立入口（physscan 构建） | DERIVED |
| `w2host.c` | cred 泄漏 + CAPSROOT + rootcmd socket；perf 采样思路参考 ghostlock-app / GhostLock-for-OnePlus（Apache-2.0），独立实现（见文件头注释） | LOCAL |
| `physscan.c` / `physscan_stub.c` | 物理内存扫描工具（独立） | LOCAL |
| `common.h` | 共享头文件 | DERIVED |
| `target_x200.h` | 目标配置头（offsets_auto.py 输出形态） | DERIVED |
| `su_blob.S` / `wallpaper_blob.S` | 内嵌汇编 blob | COPIED |

### exploit/vendored/ — IonStack 逐字组件

| 路径 | 用途 | 来源 |
|---|---|---|
| `offset.h` | IonStack 偏移头 | COPIED |
| `kernelsnitch/futex_hash.h` | futex hash 辅助 | COPIED |
| `kernelsnitch/timeutils.h` | 时序辅助 | COPIED |
| `kernelsnitch/utils.h` | 工具宏 | COPIED |
| `kernelsnitch/kernelsnitch.h` | kernelsnitch 头（本地构建变体） | DERIVED |

### exploit/assets/ + exploit/build/

| 路径 | 用途 | 来源 |
|---|---|---|
| `assets/wallpaper.webp` (+`.license`) | 内嵌壁纸 blob 资源 | COPIED |
| `build/build_glt_esync.sh` | glt 自包含 NDK 构建（glt-x200-b57-v1.0.elf） | LOCAL |
| `build/build_w2host.sh` | w2host 自包含 NDK 构建（w2host-x200-b57-v1.0） | LOCAL |

## modules/kernelsu/ — KernelSU 内核模块（vendored）

| 路径 | 用途 | 来源 | 许可证 |
|---|---|---|---|
| `kernelsu.ko`（+`.license`） | **随树预编译模块**（官方 KernelSU v3.2.5 release 资产 `android15-6.6_kernelsu.ko` + 经 `patch_vermagic.py` 做 vermagic 适配以匹配 X200 b57；in-tree） | UPSTREAM（官方 release + 设备适配） | GPL-2.0-only |
| `patch_vermagic.py` | 官方 ko 的可复现设备适配（仅改写 vermagic；输入 5933ECA4 -> 输出 187BB1BD） | LOCAL（适配脚本） | GPL-2.0-only |
| （对应源码） | 官方 KernelSU v3.2.5 `kernel/` @ `b0bc817b4e966aa6aa830834eaf6ef765d821d40`（见 SOURCE-URLS.md） | UPSTREAM | GPL-2.0-only |

## modules/permissive_restore/ — 内核模块

| 路径 | 用途 | 来源 | 许可证 |
|---|---|---|---|
| `permissive_restore.c` | 延迟 permissive 恢复模块（恢复 initialized=1、清零 GL 宿主、commit_creds、25s enforcing=0） | LOCAL（原创） | GPL-2.0-only |
| `Makefile` | Kbuild（`obj-m := permissive_restore.o`） | LOCAL | GPL-2.0-only |
| `build_permissive_restore.sh` | 参数化 WSL 构建（KSRC/CC/LD） | LOCAL | GPL-2.0-only |
| `permissive_restore.ko` | **随树预编译模块**（源码构建，in-tree） | LOCAL | GPL-2.0-only |

## tools/ — 宿主机（Windows/WSL）

### tools/scripts/ — 一键编排

| 路径 | 用途 |
|---|---|
| `root.ps1`（仓库根） | **一键入口**：build 检测 → 自动重建偏移 → 运行主链（GUI 引导） |
| `root_full_permissive_restore.ps1` | **主链** STAGE1-7；支持 `-WinOffsPath` / `-SkipPermissiveRestore` |
| `root_full_official.ps1` | legacy 对照链（仅 KSU，保持 enforcing） |
| `restart_w2.sh` | 设备端辅助（在目标上重启 W2 host） |

### tools/offset_tools/ — 偏移工具链

| 路径 | 用途 |
|---|---|
| `offsets_auto.py` | 全量偏移提取器（kallsyms + BTF + ELF → header/json） |
| `patch_ko_all.py` | ko 符号重定位（绝对地址 + `__versions` strip） |
| `rootcmd_client.py` | rootcmd socket 客户端 |
| `unpack_boot.py` | boot.img 解包 |
| `win_offs_b57.json` | b57 镜像固有偏移数据 |
| `requirements.txt` | pip 依赖（capstone, pyelftools） |

## refs/ + LICENSES/

| 路径 | 用途 |
|---|---|
| `LICENSES/Apache-2.0.txt` | SPDX 许可证文本 |
| `LICENSES/GPL-2.0-only.txt` | SPDX 许可证文本 |
