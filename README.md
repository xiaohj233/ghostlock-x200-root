<!--
SPDX-FileCopyrightText: 2026 GhostLock-X200 contributors
SPDX-License-Identifier: Apache-2.0
-->
# GhostLock-X200 v1.3.3

![Version](https://img.shields.io/badge/version-v1.3.3-blue.svg)
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
- 一键脚本 `root.ps1`：自动检测设备与内核、自动安装缺失依赖、自动生成偏移
- 偏移量从设备实时提取（kallsyms + BTF + 反汇编），不依赖硬编码地址
- **全量运行日志 + 异常重启自动诊断**：日志落盘 `log\`，panic/watchdog 时自动
  采集 pstore 等诊断并打包（AI 可读），按提示发送即可分析
- **多机型工具链（仅 X200 b57 实测适配）**：机型参数收敛为 `devices/<机型名>/`
  可分享模块，未收录机型可自动提取偏移并生成模块；但**除 X200 b57 外，其余
  机型能否 root 均需自行实测适配**（ko 需按目标内核重编 vermagic/modversions），
  工具仅提供自动提取与可行性预检（init_boot 误选、MTK 未知族等提示不推荐）
- **离线恢复（无需已 root 设备）**：仅凭 boot.img / kernel.raw / kernel.elf
  离线恢复 kallsyms + BTF（6.1 / 6.6 / 6.12）、推导 pselect 栈布局、生成
  target header；win_offs 由内核 Image 直接反汇编得到，不再依赖 vmlinux-to-elf
- **P0 物理常量自动获取**：root iomem > 设备 devicetree（非 root）> 素材 DTB
  > 待填，四级自动填充链
- **KMI 自动重打**：按目标内核自动改写 kernelsu.ko / permissive_restore.ko
  的 vermagic + ko 符号重定位
- 附带 `permissive_restore` 内核模块，修复 KernelSU 在此设备 enforcing
  模式下的网络/热点异常（见下文"与同源项目的差异"）
- 源码、构建脚本与预编译内核模块随仓库提供，许可证逐文件标注

## 支持的设备

| 设备 | 系统 / 内核 | 状态 |
|---|---|---|
| vivo X200 (PD2415) | 16.1.12.2.W10（已实测验证） | ✅ 可用 |
| vivo X200s | 16.1.12.12.W10（b57 同内核：内核 SHA256 与 X200 全等，偏移交叉验证与第三方已验证 target.h 一致；**未实体机实测**） | ⚠️ 可尝试（同内核精确命中 x200_b57 模块，需自行验证） |
| vivo X200 (PD2415) | 16.1.12.12.W10（同内核构建 b57） | ⚠️ 未实测 |
| vivo X200 (PD2415) | 其他 16.1.x，内核 b57af212129c | ⚠️ 未实测，可尝试 |
| vivo X200 (PD2415) | 内核 >= 6.6.140 | ❌ 已修复，不可用 |
| iQOO Neo11 等（同 6.6.89 MTK 内核） | 同内核 | ⚠️ 未实测，需自行二次开发 |

前提：内核 `< 6.6.140`（CVE-2026-43499 未修复）且构建为
`6.6.89-android15-8-gb57af212129c`。未实测的机型/构建需要自行验证。完整说明见
[使用说明](docs/USAGE.zh-CN.md)。

> **适配口径**：本项目**仅对表中标 ✅ 的 vivo X200（PD2415 / 16.1.12.2.W10 /
> b57 内核）做过完整真机适配**。其余所有机型（含同内核的 X200s）均为
> **未实测 / 需自行适配**：偏移可自动重建、ko vermagic 可自动重打，但能否
> root 不保证，需按目标机型/内核自行二次开发（modversions ABI 需同构建内核
> 源码重编 ko）。

> **其他机型**：非官方支持列表的机型**允许强行尝试**，工具不会阻止运行；偏移会
> 自动从素材重建，运行中异常重启会自动打包诊断日志。最终能否 root 取决于目标
> 机型/内核的二次开发适配（模块 vermagic 需按目标内核重新编译），**需自行适配**，
> 不保证直接可用。

> **MTK 机型可行性提示**：除已实测的 b57 族外，MTK（天玑/helio）未知
> 内核族**不推荐投入**——社区公开记录（vivo PD2241/天玑9200）显示 KernelSnitch
> 时序在 MTK 上不可靠（KASAN_HW_TAGS/MTE 干扰、PANIC_ON_OOPS 无试错空间、
> vivo RSC 调度器破坏 pselect/pi 链）。运行本工具选素材时会自动预检并提示。

## 与其他项目的差异

- **与 KernelSU / Magisk 等刷机型方案**：本工具**不刷机、不解锁、不触发数据
  清除**，临时 root 重启即失效，适合短期研究与测试；
- **与同源 IonStack / Neo11Plus 项目**：本仓库补齐 `permissive_restore` 模块
  修复 enforcing 下 KernelSU 网络/热点异常，并提供一键脚本、动态偏移重建与
  异常重启自动诊断。

## 快速开始

1. 下载 Release 资产 `ghostlock-x200-root-v1.3.3.zip` 并解压（zip 内含
   `prebuilt/` 二进制与 `modules/*.ko`，缺一不可）；
2. **唯一入口**：双击 `run_root.bat`（运行结束后窗口停留，报错不闪没）；或命令行：

   ```powershell
   powershell -ExecutionPolicy Bypass -File root.ps1
   ```

3. 运行日志与异常重启诊断包统一存入包内 `log\` 文件夹
   （`log\ghostlock_root_<时间戳>.log` / `log\ghostlock_diag_<时间戳>.zip`，
   控制台会打印完整路径）；诊断包按提示发送给维护者/Agent 分析。

> 多机型适配、离线生成偏移、机型模块分享、新机型编译等高级用法，见
> [使用说明 docs/USAGE.zh-CN.md](docs/USAGE.zh-CN.md)。

## 工作原理

七阶段链路：permissive（SELinux）→ kptr → KASLR base → 动态偏移 → ko 重定位
→ cred 泄漏 + CAPSROOT → 加载 permissive_restore/kernelsu → 25s 后恢复
permissive。架构与组件说明见
[docs/ARCHITECTURE.zh-CN.md](docs/ARCHITECTURE.zh-CN.md)。

## 目录结构

```
├── root.ps1                # 一键脚本（自动装依赖/生成偏移）
├── run_root.bat            # 唯一双击入口（结束后窗口停留，不自动关闭）
├── log/                    # 运行日志 + 异常重启诊断包（自动生成）
├── docs/                   # ARCHITECTURE（架构）/ FILE_MAP（逐文件映射）/ USAGE（使用说明）
├── exploit/                # 设备端利用（glt / w2host；含 IonStack 逐字与衍生源码）
├── modules/
│   ├── permissive_restore/ # 本仓库原创内核模块（GPL-2.0-only）
│   └── kernelsu/           # KernelSU 官方 v3.2.5 内核模块（GPL-2.0-only）
├── tools/                  # scripts（主链脚本 + find_adb.ps1）+ offset_tools（动态偏移工具）
│   └── offset_tools/profiles/  # 机型 profile（x200_b57.json 默认；新机型复制改名）
├── devices/                # 可分享机型模块（x200_b57/ 随仓库示例；package 生成新模块）
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
