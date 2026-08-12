<!--
SPDX-FileCopyrightText: 2026 GhostLock-X200 contributors
SPDX-License-Identifier: Apache-2.0
-->
# GhostLock-X200 使用说明

> 本文是 [README](../README.md) 的详细使用篇：环境、一键脚本、手动流程、参数、
> 常见问题都在这里。原理与组件见 [ARCHITECTURE.zh-CN.md](ARCHITECTURE.zh-CN.md)；
> 逐文件来源与许可证见 [FILE_MAP.zh-CN.md](FILE_MAP.zh-CN.md)。

## 支持的设备与版本（请先读）

| 设备 | 系统 / 内核 | 状态 |
|---|---|---|
| vivo X200 (PD2415) | **16.1.12.2.W10**（本构建已验证） | ✅ 可用 |
| vivo X200 (PD2415) | **16.1.12.12.W10** | ⚠️ 未实测 |
| vivo X200 (PD2415) | 其他 16.1.x，内核为 b57af212129c | ⚠️ 未实测，可尝试（见“适配其他构建”） |
| vivo X200 (PD2415) | 内核 >= 6.6.140 | ❌ 已永久修复（CVE-2026-43499 已修复） |
| iQOO Neo11 等 (6.6.89 MTK) | 同内核 | ⚠️ 未实测，需自行二次开发 |
| 其他 SoC / 其他内核 | — | ❌ 需要完整重新适配 |

检查你的内核：

```powershell
adb shell cat /proc/version
# 期望: 6.6.89-android15-8-gb57af212129c-...
```

内核 `< 6.6.140`（漏洞未修复）且构建为 `b57` 是必要条件，但最终是否
可用仍需在具体设备上实测。

### CVE-2026-43499 影响范围

- 受影响：2.6.39 <= Linux < 6.1.175；6.2 <= Linux < 6.6.140
- 已修复：主线 7.1（commit 3bfdc63936dd）；6.1.175 / 6.6.140 / 6.12.86 / 6.18.27 / 7.0.4
- 参考：https://nebusec.ai/research/ionstack-part-2

## 环境要求

- **Windows** + adb（自动探测：`-AdbPath` / `$env:ANDROID_ADB` / PATH）
- **Python 3**（自动探测）+ `pip install -r tools/offset_tools/requirements.txt`
- 构建（可选，仅重建 `glt` / `w2host` / `permissive_restore.ko` 时需要）：
  WSL/Linux + Android NDK（`aarch64-linux-android28-clang`）编译 exploit；
  与目标内核匹配的内核源码树（内核树 **不随仓库分发**）用于 `permissive_restore.ko`。

## 快速开始

### 一键脚本（推荐，GUI 引导）

`root.ps1`（仓库根目录）会自动做这些事：

- 检测已连接设备及其内核构建；
- **首次运行 / 构建不匹配**：通过文件对话框引导选择固件素材
  （全量 OTA zip / `payload.bin` / `boot.img` / `kernel.raw` / `kernel.elf`），
  自动识别类型、解包并为你的确切内核重建 `win_offs`，然后运行主链；
- **同为 b57 构建**：直接使用随包偏移运行主链；
- 需要时透传 `-SkipPermissiveRestore` 与 `-KsuKoPath`。

```powershell
# 唯一入口：双击 run_root.bat（结束后窗口停留，报错不闪没）

# 最简单：全自动（仅当需要重建偏移时才弹文件对话框）
powershell -ExecutionPolicy Bypass -File root.ps1

# 强制使用随包 b57 偏移，即使构建未知也直接跑（其他构建有 panic 风险）
powershell -ExecutionPolicy Bypass -File root.ps1 -Force

# 不加载 permissive_restore.ko（保持 enforcing；网络/热点可能异常）
powershell -ExecutionPolicy Bypass -File root.ps1 -SkipPermissiveRestore

# 直接指定固件素材（不弹对话框）
powershell -ExecutionPolicy Bypass -File root.ps1 -AssetPath C:\path\to\boot.img

# 关闭自动日志 / 指定日志路径 / 关闭异常重启诊断
powershell -ExecutionPolicy Bypass -File root.ps1 -NoLog
powershell -ExecutionPolicy Bypass -File root.ps1 -LogPath D:\logs\ghostlock.log
powershell -ExecutionPolicy Bypass -File root.ps1 -NoPanicDiag
```

> **运行日志**：默认自动写入包内 `log\ghostlock_root_<时间戳>.log`（启动与结束
> 时控制台都会打印完整路径），包含全部步骤与子进程原始输出；log 目录不可写时
> 自动回退 `%TEMP%`。`-NoLog` 关闭，`-LogPath` 自定义路径。

### 依赖自动安装

`root.ps1` 会先检查所有必需的宿主机工具，**仅自动下载缺失项**（默认写入
**项目根目录** `platform-tools/`、`payload-dumper-go/` 等，包内自包含；
项目根不可写时自动回退 `%LOCALAPPDATA%\GhostLock-X200\deps`）：

| 依赖 | 本机查找（按顺序） | 自动安装回退 |
|---|---|---|
| adb | `-AdbPath`、`ANDROID_ADB`、PATH、Android SDK、Scoop、Chocolatey、deps 目录 | 官方 `platform-tools-latest-windows.zip`（Google） |
| Python | `-Python`、PATH（`python`/`py`/`python3`）、常见安装目录、WindowsApps | `winget install Python.Python.3` |
| Python 依赖包 | `import capstone, elftools` 探测 | `pip install -r tools\offset_tools\requirements.txt` |
| payload 提取工具 | PATH（`payload-dumper-go`）、仓库根 `payload_dumper.py`、WSL | GitHub release 的 `payload-dumper-go` 1.3.0 |
| vmlinux-to-elf | PATH、Python 模块、WSL（**仅 derive-pselect 可选使用**） | `pip install vmlinux-to-elf`，失败回退 WSL pip；win_offs 已改为 Image 直反汇编（`winoffs-image`），不再依赖此工具 |

- `-SkipDeps` 关闭全部自动下载（离线 / 审查场景），仅打印手动安装指引。
- `-DepsDir <path>` 覆盖依赖下载目录；`-DepsInPackage` 为 v1.1.0 起默认行为
  （依赖下载到项目根目录），保留兼容。
- 所有下载来自官方 / 上游源（Google、GitHub release、PyPI）；仓库内不捆绑任何
  第三方二进制。下载仅需联网一次，之后从 deps 目录复用。

### 异常重启诊断（自动）

- 主链失败后自动判断设备是否异常重启（panic / watchdog，可恢复、无变砖风险前提）。
- 若确认异常重启（或设备长时间未恢复），自动采集诊断日志并打包
  `log\ghostlock_diag_<时间戳>.zip`：含机型/内核/启动原因、pstore（panic 瞬间
  内核日志）、MTK AEE 清单、每阶段运行标记、root 级日志快照（到达 root 阶段
  自动 dump dmesg/内核 logcat/模块/selinux）、host 完整运行日志。
- zip 内为 **AI 可读格式**（00_manifest.json 索引 + 99_READ_ME.txt 阅读指南），
  运行结束会给出指引：将该 zip 发送给维护者/Agent 分析，或自行用于二次开发调试。
- 大文件自动降体积：dmesg / pstore / root 快照均压缩为「尾部 + 关键行」摘要
  （L<行号> 对应原文行、连续重复折叠为 (xN)），panic 栈与关键错误完整保留。
- 采集全程只读、仅在主链退出后执行、不读写流式节点，**不会引发 panic**；
  `-NoPanicDiag` 可关闭。

### vmlinux-to-elf 不再是 win_offs 依赖

偏移生成（winoffs）已改为 capstone 直接反汇编内核 Image（`winoffs-image`，
符号用离线 kallsyms，boot.img 自动提取内核段 + 解压），**无需 vmlinux-to-elf**。
vmlinux-to-elf 仅在 `derive-pselect`（pselect 栈布局推导）时可选使用：Windows
装不上（minilzo 需 MSVC）会自动回退 WSL kali-linux；两者都不可用时跳过
pselect 推导，使用默认值 0（b57 已验证）。本工具支持直接以 `kernel.elf` 为素材。

### 手动脚本

| 脚本 | 说明 | 状态 |
|---|---|---|
| `tools\scripts\root_full_permissive_restore.ps1` | **主链**：permissive + 可选 KSU + permissive_restore 25s permissive 恢复；热点/网络正常。动态偏移。参数：`-WinOffsPath`（自定义偏移 json）、`-SkipPermissiveRestore`（不加载 permissive_restore）、`-KsuKoPath`、`-AdbPath`、`-Serial`。 | ✅ 推荐 |
| `root.ps1` | 主链的一键封装（见上文）。 | ✅ 推荐 |
| `tools\scripts\root_full_official.ps1` | **Legacy 对照**：不含 permissive_restore 的官方链（保持 enforcing）。硬编码 b57 地址 - 非动态。 | ⚠️ legacy |

```powershell
# 手动主链:
powershell -File tools\scripts\root_full_permissive_restore.ps1
# 手动、不加载 permissive_restore 模块:
powershell -File tools\scripts\root_full_permissive_restore.ps1 -SkipPermissiveRestore
```

**预编译资产**：`permissive_restore.ko` **随 Git 树分发**
（`modules/permissive_restore/permissive_restore.ko`，由随包源码构建，GPL-2.0-only）
——无需下载。其余二进制作为 GitHub Release 资产发布，不进 Git 树。下载 Release
zip（或 `release-assets` 文件夹）后按脚本期望的文件名放入包内（按需重命名）：

| Release 资产 | 放置为 |
|---|---|
| `ksud-32525` | `prebuilt/ksud` |
| `glt-x200-b57-v1.0.elf` | `prebuilt/glt_esync` |
| `w2host-x200-b57-v1.0` | `prebuilt/w2host` |

脚本会打印确切缺失的资产名及获取位置。

**KernelSU 内核模块**：随包内置 `modules/kernelsu/kernelsu.ko`
（GPL-2.0-only，官方 KernelSU v3.2.5 release 资产 `android15-6.6_kernelsu.ko`，
vermagic 与本机内核匹配：6.6.89-android15-8-gb57af212129c）。对应源码为官方
KernelSU v3.2.5 `kernel/` 源码 @ `b0bc817b`
（https://github.com/tiann/KernelSU，GPL-2.0-only；见 SOURCE-URLS.md）。如需使用
自建模块，可通过 `-KsuKoPath <path>` 或 `$env:KSU_KO_PATH` 传入覆盖。未提供内核
模块时跳过 KSU 阶段，permissive_restore/permissive 链路照常运行。

链路流程：环境检测 -> 镜像偏移（`win_offs_b57.json`）-> STAGE1 permissive ->
STAGE2 kptr -> STAGE3 base -> STAGE3.4 动态偏移（kallsyms + BTF + 反汇编）->
STAGE3.5 ko repatch + push -> STAGE4 cred 泄漏（运行时注入采样窗口/内存范围）->
STAGE5 CAPSROOT -> STAGE6 INSMOD permissive_restore（参数化）[+ kernelsu] ->
STAGE7 25s permissive 验证 + 网络。

**验证**：

```powershell
adb shell getenforce
# 期望: Permissive
# （启用 KSU 时）adb shell /data/local/tmp/ksud debug version -> 32525
```

## permissive_restore 模块

官方 KernelSU ko 会强制 `setenforce(true)`；其替换的 sepolicy 在 enforcing 下
存在缺陷（socket SID 解析为 `unlabeled`）-> netd/mdnsd 发包被拒 -> 断网/热点异常。

`modules/permissive_restore/` 是一个小型内核模块（P0 地址参数化；脚本按 boot
传入，跨构建无需重编译）。加载时：

1. 恢复 `selinux_state.initialized = 1`（STAGE1 的 8 字节写会清掉它，否则每个
   新启动的应用都会崩溃），
2. `prepare_kernel_cred(&init_task)` + `commit_creds` -> uid0 完整权限，
3. 一个延迟线程在 25 秒后字节写 `enforcing = 0`（单字节；不碰
   `initialized`/`policycap`）。

顺序很重要：先 INSMOD permissive_restore，再 kernelsu。KSU 加载后 rootcmd
socket 会被 SELinux 阻断，只能靠 permissive_restore 的延迟线程把 enforcing
改回 0。

`permissive_restore.c` 采用 **GPL-2.0-only** 许可（见
`LICENSES/GPL-2.0-only.txt`）；`MODULE_LICENSE("GPL")` 是对应的加载器声明。

> **它为什么存在**
> 没有它时，官方 KernelSU ko 会强制 enforcing，其缺陷 sepolicy 会在此设备上
> 破坏热点/网络——这一点已在验证中复现并确认。该模块：
> - 源码就在本仓库（`modules/permissive_restore/`，GPL-2.0-only）；
> - **可选**：传 `-SkipPermissiveRestore`（或在 `root.ps1` 中选择该选项）即可
>   不加载它运行链路。此时保持 enforcing，热点/网络可能异常——这是已知权衡；
> - 代码量小，方便审查：它只恢复 SELinux 状态并授予 uid0（与 STAGE5 exploit 已
>   获得的权限相同）；无网络访问、无持久化、重启即卸载（仅临时 root）。

## 偏移自动化

| 偏移 | 来源 |
|---|---|
| enforcing/kptr P0 地址 | `tools/offset_tools/win_offs_b57.json`（镜像固有）+ boot 时计算 |
| CAPSROOT capsym | kallsyms 自动选择 bss `.__key` 符号（位条件匹配） |
| w2host 采样窗口 / 范围 | kallsyms + 反汇编 + 真实设备 MemTotal |
| 结构偏移（cred+0x38, task+0x820, ...） | 设备 BTF（`/sys/kernel/btf/vmlinux`） |
| ko 符号重定位 | `tools/offset_tools/patch_ko_all.py`（kallsyms + `__versions` strip） |

自动处理的已知坑：

- 本地构建的 ko 带有 CRC=0 的 `__versions` 表，设备加载器会拒绝（`INSMOD -1 8`
  ENOMEM）；`patch_ko_all.py` 会将其 strip。
- 异常重启可能损坏 /data inode；脚本使用每次运行唯一后缀（`glt_<tag>` /
  `rootcmd_<tag>.sock` 等）。

### 全量偏移提取器（`tools/offset_tools/offsets_auto.py`）

| 子命令 | 输入 | 输出 |
|---|---|---|
| `all` | kallsyms + BTF + ELF + outdir | target_x200.h + win_offs.json + offsets.json |
| `header` | kallsyms + BTF | 完整 target_x200.h（符号 + BTF 结构偏移；`--w2host` 同步，`--diff` 对比） |
| `winoffs` | kernel ELF | win_offs.json（physmap_base + sym_offs + w2host 窗口） |
| `live` | kallsyms + BTF + win_offs | offsets.json（运行时动态值，同 STAGE3.4） |

### 适配其他构建（同平台，新 OTA）

1. 使用**独立安装、具有明确许可证的 payload 提取工具**从新固件 boot.img 提取
   内核 ELF（`tools/offset_tools/unpack_boot.py` 可自行处理 boot.img 格式）。
2. 启动一次（或使用 kallsyms 转储 + 设备 BTF）并重新生成全部偏移：
   ```bash
   python tools/offset_tools/offsets_auto.py all <kallsyms.txt> <vmlinux.btf> <kernel.elf> <outdir>
   # -> outdir/target_x200.h + win_offs.json + offsets.json
   ```
3. 用生成的 `target_x200.h` 重建 glt
   （`bash exploit/build/build_glt_esync.sh`；w2host.c 可通过
   `--w2host exploit/src/w2host.c` 自动同步 TASK_CRED_OFF/TASK_COMM_OFF 后重建）。
4. 将 `win_offs.json` 放入 `tools/`，`permissive_restore.ko` 无需重编译（脚本
   运行时传入 P0 值）。
5. 运行 `tools\scripts\root_full_permissive_restore.ps1`。

> 以上是适配流程，不代表适配后一定可用；最终仍需在目标设备上实测验证。

## 从源码构建（可选）

```bash
bash modules/permissive_restore/build_permissive_restore.sh -k <kernel-tree>   # permissive_restore.ko（需要内核树；随包 .ko 已由源码构建）
bash exploit/build/build_glt_esync.sh                        # glt-x200-b57-v1.0.elf
bash exploit/build/build_w2host.sh                           # w2host-x200-b57-v1.0
```

## 已知限制

1. **临时 root**：每次冷启动后需重跑（约 1-2 分钟）。
2. **su 路径风险**：KernelSU su 在某些场景可能触发 vivo 检测 panic；默认改用
   rootcmd。
3. **异常重启副作用**：强制重启（如 sysrq）可能损坏 /data 数据（脚本使用唯一
   后缀避免 inode 问题；蓝牙配对可能需要重新做一次）。
4. **不要升级系统**：较新的 vivo 构建可能修复 CVE-2026-43499（>= 6.6.140 已
   修复）。

## 常见问题 FAQ

### Q: 会把手机搞坏/变砖吗？
A: 不会。本链路不写系统分区、不改 bootloader、不触发数据清除。最坏情况是内核
panic，重启即可恢复，无变砖风险。风险操作前脚本都有 gate 检查。

### Q: 需要解锁 bootloader 或刷机吗？
A: 不需要。无需解锁、无需刷机、不触发数据清除——这正是本工具与 KernelSU/Magisk
刷机型方案的根本区别（见 README“与其他项目的区别”）。

### Q: root 是永久的吗？
A: 不是。这是临时 root：每次冷启动后需重跑一次（约 1-2 分钟）。适合短期研究/
测试，不适合当作日常持久 root 使用。

### Q: permissive_restore 是后门吗？
A: 不是。它源码在本仓库（GPL-2.0-only）、可选（`-SkipPermissiveRestore`）、
代码量小：只恢复 SELinux 状态 + 授予 uid0（与 exploit 已获得的权限相同）；
无网络访问、无持久化、重启即卸载。它存在的原因是修复官方 KernelSU ko 在此
设备上导致的断网/热点异常（详见上文“permissive_restore 模块”）。

### Q: 为什么不直接用 su，而用 rootcmd？
A: KernelSU 的 su 在某些场景可能触发 vivo 检测 panic；rootcmd 是本项目默认的
root 通道，不经过 su，也就不会触发这类检测。

### Q: 断网/离线能用吗？
A: 能。依赖自动下载只需联网一次，之后从项目根目录（或回退的
`%LOCALAPPDATA%\GhostLock-X200\deps`）复用；`-SkipDeps` 可关闭自动下载
（离线/审查场景）。设备端网络在 STAGE7 permissive 恢复后正常（实测网络可用）。

### Q: 升级系统后还能用吗？
A: 不一定。内核 >= 6.6.140 已修复 CVE-2026-43499，无法使用。升级前先
`adb shell cat /proc/version` 确认内核版本。

### Q: `root_full_official.ps1` 和主链有什么区别？
A: 主链（`root_full_permissive_restore.ps1`）= permissive + 可选 KSU +
permissive_restore（网络/热点正常，动态偏移，推荐）；official =
无 permissive_restore 的对照链（保持 enforcing，网络可能异常，硬编码 b57
地址，仅供对照/兼容，不推荐日常使用）。

### Q: 会清空我的数据吗？
A: 不会主动清空。但异常重启（如 sysrq 强制重启）可能损坏 /data inode（脚本
已用唯一后缀缓解；蓝牙配对可能需要重做一次）。正常流程不影响数据。

### Q: 支持哪些设备？
A: 核心条件是 vivo X200 (PD2415) + 内核 `6.6.89-android15-8-gb57af212129c`
构建（< 6.6.140，漏洞未修复）。除已实测的 16.1.12.2.W10 外，其他机型/构建
均未实测，可尝试自行适配（同内核的 iQOO Neo11 等需重新生成偏移，其他
SoC/内核需完整重新开发）。非官方支持列表机型**允许强行尝试**：偏移自动重建、
异常重启自动出诊断包，最终可用性取决于二次开发适配（模块 vermagic 需按目标
内核重新编译），不保证直接可用。详见上文“支持的设备与版本”。
