<!--
SPDX-FileCopyrightText: 2026 GhostLock-X200 contributors
SPDX-License-Identifier: Apache-2.0
-->
# GhostLock-X200 v1.3.0

![Version](https://img.shields.io/badge/version-v1.3.0-blue.svg)
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
- **全量运行日志**：默认自动写入包内 `log\ghostlock_root_<时间戳>.log`，各步骤
  原始输出全部落盘，失败时控制台直接打印原始输出，不再吞错
- **异常重启诊断**：运行中发生内核 panic / watchdog 异常重启时，自动采集
  pstore、运行标记、root 级快照等诊断日志并打包 `ghostlock_diag_<时间戳>.zip`
  （AI 可读格式，存于 `log\` 文件夹），按控制台指引发送给维护者/Agent 分析即可
- **adb 智能定位**：多位置探测 + 可用性校验，找不到时自动下载到包内
- 依赖默认下载到**项目根目录**（包内自包含，可整体拷贝），不可写时自动回退
- **多机型 profile 参数化**：偏移工具按 `tools/offset_tools/profiles/<device>.json`
  读取机型常量（KIMAGE_TEXT_BASE / P0_* / 直映射 / vmemmap / physmap_base /
  内核 release / SoC），不再硬编码 b57；新机型复制 `x200_b57.json` 改名填写即可
- **机型可行性预检**：素材选择后自动执行预检，输出
  `推荐 / 可尝试 / 不推荐` 与逐项原因——覆盖 init_boot 误选（kernel_size=0）、
  内核是否已知族、SoC、PANIC_ON_OOPS 等；**MTK 未知族明确提示不推荐**（附社区
  失败证据，避免空耗）
- **KMI 自动重打**：`-KernelRelease <完整UTS_RELEASE>` 与 profile 不同时，
  自动改写 kernelsu.ko / permissive_restore.ko 的 vermagic 至目标内核
- **离线恢复**：无需已 root 设备，仅凭 boot.img / kernel.raw / kernel.elf
  即可离线恢复 kallsyms + BTF（支持 6.1 / 6.6 / 6.12 内核分支），无设备也能生成
  target header（root.ps1 素材流程自动执行）
- **pselect 栈布局自动推导**：反汇编 pselect/futex 调用链自动得出
  `PSELECT_WAITER_WORD_SHIFT`（b57 实测 = 0，与真机调参一致），不再手动固化
- **P0 物理常量自动获取**：`detect-p0` 从已 root 设备的 /proc/iomem 自动
  推导 phys_offset / kernel_phys_load（含 6 项反向校验），支持文件输入与 adb 双通道
- **机型模块化 + 可分享**：机型参数与偏移产物收敛为 `devices/<机型名>/`
  目录（device.json + win_offs.json + offsets.json + target.h + pselect.json +
  manifest.json）；**设备在线自动匹配模块**（/proc/version 精确命中即直接用）；
  未收录机型自动提取并生成新模块（可分享）；导入他人模块解压到 `devices/` 后
  同机型自动命中；除分享模块外不再硬编码机型参数
- **P0 物理常量自动获取**：`detect-p0` 新增 `--devicetree` 模式（**非 root**
  读设备 `/sys/firmware/devicetree/base/memory/reg` 自动推 phys_offset）；package 支持
  `--vendor-boot`（v3/v4 boot 的 DTB 段）离线解析 memory 节点自动填 P0；
  自动顺序 root iomem > devicetree > 素材 DTB > 待填
- **win_offs 去 vmlinux-to-elf 依赖**：新增 `winoffs-image` 子命令
  （capstone 直接反汇编内核 Image + 离线 kallsyms，boot.img 无需转换 ELF 也能出
  w2host 偏移窗口，已验证与 b57 ELF 产物全等）
- **exploit 编译常量参数化**：`PSELECT_ROUTE_NFDS` 由机型模块 target.h
  注入（derive-pselect 推导），`main.c` 测试读地址改宏表达式；build 脚本 `-t` 按
  机型模块编译
- **新机型流程 package 主导**：未收录机型素材直接走
  `offline → winoffs-image → pselect → header → 机型模块`，**不再依赖
  vmlinux-to-elf**（仅 derive-pselect 可选使用）；`task_cred_off` 由素材 BTF
  自动推导（不同构建的 task_struct.cred 不同，如 b57=0x820、其他构建=0x8c8），
  避免 w2host 采样窗口因偏移错误而空
- **非 b57 prebuilt 门禁**：主链优先使用机型模块自带
  `devices/<id>/prebuilt/` 产物；非 b57 且模块无产物时**询问后默认不跑**
  （b57 预编译二进制硬编码偏移，强跑有 panic 风险），提示用 build 脚本 `-t`
  重编译后放入模块
- **KMI 自动触发**：机型模块生成后自动读取模块 `kernel_release`，检测
  kernelsu.ko / permissive_restore.ko 的 vermagic 不匹配即自动重打，主链使用
  重打产物（`-KernelRelease` 保留为手动覆盖）
- 附带 `permissive_restore` 内核模块，用于修复 KernelSU 在此设备 enforcing
  模式下的网络/热点异常（见下文“与同源项目的差异”）
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

> **其他机型**：非官方支持列表的机型**允许强行尝试**，工具不会阻止运行；偏移会
> 自动从素材重建，运行中异常重启会自动打包诊断日志。最终能否 root 取决于目标
> 机型/内核的二次开发适配（模块 vermagic 需按目标内核重新编译），不保证直接可用。

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

1. 下载 Release 资产 `ghostlock-x200-root-v1.3.0.zip` 并解压（zip 内含
   `prebuilt/` 二进制与 `modules/*.ko`，缺一不可）；
2. **唯一入口**：双击 `run_root.bat`（运行结束后窗口停留，报错不闪没）；或命令行：

   ```powershell
   powershell -ExecutionPolicy Bypass -File root.ps1
   ```

3. 运行日志与异常重启诊断包统一存入包内 `log\` 文件夹
   （`log\ghostlock_root_<时间戳>.log` / `log\ghostlock_diag_<时间戳>.zip`，
   控制台会打印完整路径）；诊断包按提示发送给维护者/Agent 分析。

多机型适配参数：

```powershell
# 使用指定机型 profile（默认 profiles/x200_b57.json）
powershell -ExecutionPolicy Bypass -File root.ps1 -Profile tools\offset_tools\profiles\x200_b57.json

# 目标内核与 profile 不同时，自动重打 ko vermagic
powershell -ExecutionPolicy Bypass -File root.ps1 -KernelRelease "6.6.89-android15-8-gb57af212129c-abogki457297774-4k"
```

新机型 profile 字段说明：`kernel_release`（设备 /proc/version 第 3 字段，完整
UTS_RELEASE）、`family`（内核族标识）、`soc`（dimensity/snapdragon 等）、
`kimage_text_base`/`p0_*`/`identity_*`/`direct_map_*`/`vmemmap_start`/
`physmap_base`（P0 常量，来自 vmlinux 基址与直映射布局）、`task_cred_off`、
`verified`（真机验证通过才置 true）。偏移自动从素材重建，ko vermagic 自动重打，
但**模块 modversions ABI 仍按编译时内核**——非同构建内核 insmod 可能失败。

离线生成偏移（无需设备）：

```powershell
# 1) 离线恢复 kallsyms + BTF (支持 boot.img / kernel.raw / kernel.elf; 6.1/6.6/6.12)
python tools\offset_tools\offsets_auto.py offline C:\path\boot.img --out-dir C:\tmp\off

# 2) 推导 pselect 栈布局 (需 kernel.elf + 离线产物 + objdump, Windows 或 WSL kali)
python tools\offset_tools\offsets_auto.py derive-pselect C:\path\kernel.elf ^
  --kallsyms C:\tmp\off\kallsyms.txt --btf C:\tmp\off\vmlinux.btf -o C:\tmp\off\pselect.json

# 3) 生成 target header
python tools\offset_tools\offsets_auto.py header C:\tmp\off\kallsyms.txt C:\tmp\off\vmlinux.btf ^
  -o target.h --profile tools\offset_tools\profiles\x200_b57.json --pselect C:\tmp\off\pselect.json

# 4) P0 物理常量 (已 root 同型号设备): 文件输入或 adb 自动
python tools\offset_tools\offsets_auto.py detect-p0 --iomem iomem.txt
python tools\offset_tools\offsets_auto.py detect-p0 --serial <SN> --write-profile tools\offset_tools\profiles\<机型>.json
```

root.ps1 素材流程会自动串联 1-3（选素材后离线恢复 + pselect + header），主链成功后
自动尝试 detect-p0。

机型模块与分享：

```powershell
# 查看已安装模块 / 校验模块完整性
python tools\offset_tools\offsets_auto.py verify-device x200_b57

# 生成新机型模块 (未收录机型; 自动提取全套, P0 物理常量待填)
python tools\offset_tools\offsets_auto.py package C:\path\boot.img --out devices\my_device --soc dimensity

# 分享: 打包 devices\<机型名>\ 为 zip (含 manifest.json 校验和), 或直接拷贝目录
# 导入: 解压到本项目 devices\ 下; 设备连接后按 /proc/version 自动精确命中

# 编译 exploit 到指定机型模块 (默认 x200_b57)
bash exploit/build/build_glt_esync.sh -t my_device
bash exploit/build/build_w2host.sh -t my_device
```

> **模块分享约定**：`devices/` 是唯一可分享的机型目录；模块内偏移/参数为事实数据。
> `kernel_release` 相同即精确命中（零提取直接使用）；仅 `family` 相同视为"同族可
> 尝试"（需重新生成偏移）。ko 不入模块，导入后按 kernel_release 自动重打 vermagic。

新机型编译：

```bash
# 1) 生成机型模块 (boot.img 即可, 无需 vmlinux-to-elf; P0 自动或待填)
python tools\offset_tools\offsets_auto.py package C:\path\boot.img ^
  --out devices\my_device --vendor-boot C:\path\vendor_boot.img --soc dimensity

# 2) 编译 exploit: root.ps1 门禁处可自动完成 (WSL kali NDK 或自动下载 NDK):
#    - 自动: 运行 root.ps1 时提示 "是否自动编译本机型 exploit 产物? (y/N)" -> y
#      自动用 WSL kali NDK / 下载 NDK 编译 glt -> devices\<id>\prebuilt\glt_esync
#    - 手动: 用 Android NDK (aarch64-linux-android28-clang) 按机型模块编译
bash exploit/build/build_glt_esync.sh -t my_device    # -> devices\my_device\prebuilt\glt_esync
#    注: 只有 glt_esync 需要按机型编译 (target.h 编译期注入偏移);
#    w2host 的采样窗口/候选范围已运行时注入 (W2_CRED_IPS 等), 无需重编,
#    直接复用仓库 prebuilt\w2host (build_w2host.sh 仅用于修改 w2host.c 本身).

# 3) 内核模块: vermagic 自动重打 (root.ps1 -KernelRelease), 但 modversions ABI
#    仍需同构建内核源码重编 kernelsu/permissive_restore (非同构建可能 insmod 失败)
```

NDK 获取：Android Studio SDK Manager 或
[android-ndk 官方下载](https://developer.android.com/ndk/downloads)（r29+）。
本机 WSL kali 已装 NDK（`/usr/lib/android-ndk`）时自动编译零下载；否则 root.ps1
询问后自动下载 NDK r28（Windows, ~1.1GB）到项目根。
非 b57 机型必须按该机型模块 target.h 重编译 glt_esync（自动编译或手动），否则
root.ps1 会询问"是否仍用 b57 预编译产物强跑？"（默认不跑，风险自担）。
b57 命中时行为不变（直接用仓库 prebuilt/）。

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
