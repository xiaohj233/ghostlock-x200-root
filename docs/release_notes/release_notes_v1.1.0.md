# GhostLock-X200 v1.1.0

## 本版定位

- 以 README「支持的设备」所列机型（b57 内核）为**参考实现**，同时面向**自行二次
  开发适配其他机型**：偏移全程从设备实时提取（kallsyms + BTF + 反汇编），不依赖
  硬编码地址；配合本版新增的异常重启诊断，可在**非官方支持机型上强行尝试**，
  并自动收集可供分析的完整日志，作为二次开发的调试依据。
- 非官方支持机型 = **允许尝试，风险自担**：工具不会阻止运行，但最终能否 root
  取决于目标机型/内核的适配程度，请先阅读下方「非支持机型使用与二次开发」。

## 修复（关键）

- **WSL 路径转换修复**：旧版仅在系统临时目录位于特定盘符时生效，其余场景
  `vmlinux-to-elf` 在 WSL 里打不开 `kernel.raw`，导致误报
  `[X] vmlinux-to-elf 转换失败 (无输出 kernel.elf)`。新版支持任意盘符自动转换为
  `/mnt/<盘符>/`，已在真实内核上复现旧问题并验证修复。
- **误选无内核镜像提示**：kernel.raw 过小（<1MB）时明确提示改选 `boot.img`
  （payload 的 boot 分区）或全量包 zip，而不是报看不懂的转换失败。
- **unpack_boot.py**：镜像中无内核（`kernel_size==0`）时提前报错提示。

## 新增

- **全量日志**：默认自动写入 `%TEMP%\ghostlock_root_<时间戳>.log`，各步骤原始输出
  （payload 提取 / unpack_boot / vmlinux-to-elf / winoffs）全部落盘；失败时控制台
  直接打印原始输出最后 20 行，不再吞错。可用 `-NoLog` 关闭，`-LogPath` 指定路径。
- **run_with_log.bat**：兼容旧版 release 的日志采集器，放在 root.ps1 同目录双击
  运行，日志固定写到桌面 `ghostlock_log.txt`，末尾 `pause` 防止闪退
  （PowerShell 5.1 下需 Start-Transcript 才能捕获 Write-Host 输出）。
- **异常重启诊断（自动）**：主链失败后自动判断设备是否异常重启（panic/watchdog），
  并采集诊断日志打包为 `ghostlock_diag_<时间戳>.zip`：含机型/内核/启动原因、
  pstore（panic 瞬间内核日志）、MTK AEE 清单、每阶段运行标记、root 级日志快照
  （到达 root 阶段时自动 dump 完整 dmesg/内核 logcat/模块/selinux 状态）、
  host 完整运行日志。zip 内为 AI 可读格式（00_manifest.json 索引 +
  99_READ_ME.txt 阅读指南），运行结束会给出指引：将该 zip 发送给维护者/Agent 分析，
  或自行用于二次开发调试。采集全程只读、仅在主链退出后执行、不读写流式节点，
  不会引发 panic；可用 `-NoPanicDiag` 关闭。
- **依赖打包分发**：`-DepsInPackage`（或 `-DepsDir <目录>`）可让 adb /
  payload-dumper-go 等依赖下载到项目根目录随包分发，方便做离线包；默认仍兼容旧的
  `%LOCALAPPDATA%\GhostLock-X200\deps` 位置，新旧位置都会自动识别，
  payload-dumper-go 不会重复下载。
- **adb 智能定位**：找不到 adb 时自动按更多位置探测（PATH / Android SDK /
  Android Studio / Scoop / Chocolatey / WinGet 包目录 / 包内 platform-tools /
  依赖目录 / 有界递归搜索），并对每个候选执行 `adb version` 校验，跳过残缺或
  非官方文件；主链与一键脚本共用同一套探测逻辑（tools/scripts/find_adb.ps1）。
- 素材类型支持新增 `.raw`（kernel.raw 可直接作为输入，跳过解包环节）。

## 非支持机型使用与二次开发（请先阅读）

- **允许强行尝试**：非官方支持机型可直接运行本工具，脚本会自动从素材
  （全量包 zip / payload.bin / boot.img / kernel.raw / kernel.elf）重建偏移，
  无需任何额外参数；若内核构建检测失败，可用 `-Force` 跳过 build 检测直接运行
  随包偏移（仅建议同内核构建场景，风险自担）。
- **预期会失败的点**：预编译内核模块（kernelsu.ko / permissive_restore.ko）的
  vermagic 为目标内核专用，其他内核构建无法 `insmod` 加载；偏移生成工具也含
  目标内核实证硬编码值（如 task_cred_off）。这些均属**预期行为**，说明需要按
  目标内核重新编译/适配模块（二次开发），不保证直接可用。
- **调试路径**：运行中出现异常重启（panic/watchdog，可恢复、无变砖风险前提）时，
  工具会自动打包 `ghostlock_diag_<时间戳>.zip`；zip 内 pstore 记录了 panic 瞬间
  内核日志，运行标记（glt_seq_*）定位 panic 前最后动作，host 日志定位失败阶段，
  可据此判断是机型不兼容还是适配进度问题。
- **适配参考**：offset_tools（kallsyms/BTF/反汇编）与主链均为设备侧动态提取，
  二次开发时重点核对 BTF 结构偏移与模块 vermagic。

## 已知限制

- 官方支持机型与内核前提见 README.md「支持的设备」。
- `vmlinux-to-elf` 依赖：Windows 下 `pip install vmlinux-to-elf`，或 WSL
  kali-linux 中 `pip3 install vmlinux-to-elf`（推荐，转换更快更稳）。
