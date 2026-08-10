<!--
SPDX-FileCopyrightText: 2026 GhostLock-X200 contributors
SPDX-License-Identifier: Apache-2.0
-->
# GhostLock-X200 v1.0

![Version](https://img.shields.io/badge/version-v1.0-blue.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%2B%20Android-orange.svg)
![Kernel](https://img.shields.io/badge/kernel-6.6.89%20b57-lightgrey.svg)

> ⚠️ **法律与安全声明（请务必先阅读）**
>
> 本仓库仅用于**安全研究与教育目的**，并且**只允许在你自己拥有、或已获得明确
> 书面授权的设备上使用**。未经授权对他人设备使用本工具，可能违反当地法律法规。
> 使用本工具可能导致设备异常重启、数据损坏、系统异常、保修失效等后果，请自行
> 评估风险。**作者不对任何直接或间接损害承担责任，亦不对任何滥用行为负责。**
> 继续阅读或使用本仓库，即表示你已理解并同意自行承担全部风险与责任。

针对 **vivo X200（PD2415 / Dimensity 9400 / b57 内核）**、基于
CVE-2026-43499（GhostLock）内核漏洞实现的**临时 root 工具链**：不需要解锁
Bootloader、不需要刷机、不会清空数据。运行后获得临时 root，重启后失效。

[功能特性](#功能特性) • [支持的设备](#支持的设备) • [与其他项目的差异](#与其他项目的差异) •
[快速开始](#快速开始) • [工作原理](#工作原理) • [目录结构](#目录结构) • [许可证](#许可证与来源)

---

## 功能特性

- 不需要解锁 Bootloader、不需要刷机、不触发数据清除
- 临时 root：重启即失效，不写入系统分区
- 提供一键脚本 `root.ps1`：自动检测设备与内核、自动安装缺失依赖、自动生成偏移
- 偏移量从设备实时提取（kallsyms + BTF + 反汇编），不依赖硬编码地址
- 附带 `permissive_restore` 内核模块，用于修复 KernelSU 在此设备 enforcing
  模式下的网络/热点异常（见下文“与同源项目的差异”）
- 源码、构建脚本与预编译内核模块随仓库提供，许可证逐文件标注

## 支持的设备

| 设备 | 系统 / 内核 | 状态 |
|---|---|---|
| vivo X200 (PD2415) | 16.1.12.2.W10（已实测验证） | ✅ 可用 |
| vivo X200 (PD2415) | 16.1.12.12.W10（同内核构建 b57） | ⚠️ 未实测 |
| vivo X200 (PD2415) | 其他 16.1.x，内核 b57af212129c | ⚠️ 未实测，可尝试 |
| vivo X200 (PD2415) | 内核 >= 6.6.140 | ❌ 已修复，不可用 |
| iQOO Neo11 等（同 6.6.89 MTK 内核） | 同内核 | ⚠️ 未实测，需自行二次开发 |

前提：内核 `< 6.6.140`（CVE-2026-43499 未修复）且构建为
`6.6.89-android15-8-gb57af212129c`。未实测的机型/构建需要自行验证。完整说明见
[使用说明](docs/USAGE.zh-CN.md)。


## 快速开始

```powershell
# 下载 Release 资产放入包内后：
powershell -ExecutionPolicy Bypass -File root.ps1
```

详细流程（一键脚本、依赖安装、手动脚本、参数表、常见问题）见
[使用说明 docs/USAGE.zh-CN.md](docs/USAGE.zh-CN.md)。

## 工作原理

七阶段链路：permissive（SELinux）→ kptr → KASLR base → 动态偏移 → ko 重定位
→ cred 泄漏 + CAPSROOT → 加载 permissive_restore/kernelsu → 25s 后恢复
permissive。架构与组件说明见
[docs/ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md)。

## 目录结构

```
├── root.ps1                # 一键脚本（自动装依赖/生成偏移）
├── docs/                   # ARCHITECTURE（架构）/ FILE_MAP（逐文件映射）/ USAGE（使用说明）
├── exploit/                # 设备端利用（glt / w2host；含 IonStack 逐字与衍生源码）
├── modules/
│   ├── permissive_restore/ # 本仓库原创内核模块（GPL-2.0-only）
│   └── kernelsu/           # KernelSU 官方 v3.2.5 内核模块（GPL-2.0-only）
├── tools/                  # scripts（主链脚本）+ offset_tools（动态偏移工具）
├── refs/                   # 上游参考表（版本固定）
├── LICENSES/               # SPDX 许可证文本（REUSE）
├── LICENSE / NOTICE / THIRD_PARTY_NOTICES.md / SOURCE-URLS.md
└── REUSE.toml
```

每个文件的用途、来源（COPIED / DERIVED / LOCAL）与许可证见
[docs/FILE_MAP.zh-CN.md](docs/FILE_MAP.zh-CN.md)。

## 许可证与来源

- 项目原创代码：**Apache-2.0**（见 LICENSE / NOTICE）；
  `modules/permissive_restore/` 为 **GPL-2.0-only**；
- `exploit/` 含 NebuSec/CyberMeowfia IonStack 的逐字与衍生代码（Apache-2.0，
  commit 已固定），以及 boxiaolanya2008/Neo11Plus、YuKongA/ghostlock-app 的
  适配参考（Apache-2.0）；
- `modules/kernelsu/kernelsu.ko` 为官方 KernelSU v3.2.5 release 资产
  `android15-6.6_kernelsu.ko`（GPL-2.0-only）经 vermagic 适配后的产物：
  只改写了 .modinfo 的 vermagic 字符串以匹配 X200 b57 内核，不改任何代码
  （复现脚本 `modules/kernelsu/patch_vermagic.py`，SHA256 与来源见
  THIRD_PARTY_NOTICES.md / SOURCE-URLS.md）；
- `prebuilt/ksud`（Release 资产）为官方 APK 中未修改的 `libksud.so`
  （GPL-3.0-or-later）。

完整清单见 [NOTICE](NOTICE)、[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)、
[SOURCE-URLS.md](SOURCE-URLS.md)。

## 致谢

- [NebuSec / CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) — IonStack
  原始研究（CVE-2026-43499）
- [tiann/KernelSU](https://github.com/tiann/KernelSU) — KernelSU v3.2.5
- [boxiaolanya2008/CVE-2026-43499-Neo11Plus](https://github.com/boxiaolanya2008/CVE-2026-43499-Neo11Plus)、
  [YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)、
  [p2p3p/GhostLock-for-OnePlus](https://github.com/p2p3p/GhostLock-for-OnePlus)
  — 适配与架构参考
