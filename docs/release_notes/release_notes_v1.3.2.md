# GhostLock-X200 v1.3.2

## 本版说明

- v1.3.2 为 v1.3.1 的**修复版**，功能全貌见 `release_notes_v1.3.0.md`；
  本版仅列出相对 v1.3.1 的新增。

## 修复（相对 v1.3.1）

- **detect-p0 主链集成修复**：机型精确命中时主链成功后自动获取 P0 物理常量
  原本必然失败（脚本路径变量仅在部分分支赋值），现改为全分支可用，并显式
  指定设备串号、失败 3 秒后自动重试一次、失败时输出真实原因（不再静默）。
- **adb 路径兼容**：自动提取脚本的 adb 调用优先使用 `ANDROID_ADB` 环境变量
  （root.ps1 已设置），未设置时回落 PATH，避免 adb 不在 PATH 时失败。

## 改进（相对 v1.3.1）

- **设备稳定等待（uptime>240s）**：等待期间每 30 秒打印进度提示；支持按
  `S` 键跳过、`run_root.bat -SkipUptimeWait` 参数跳过或运行中询问确认跳过，
  并明确提示"设备未稳定可能导致内核 panic"（仅建议在设备已稳定时跳过）。
- **设备重启等待上限**：主链失败后等待设备重启回来由 12 分钟缩短为
  3 分钟（panic 后重启通常 1-2 分钟），等待期间打印进度，上线即继续。

## 使用

```powershell
# 唯一入口（Windows）：
run_root.bat
# 或：powershell -ExecutionPolicy Bypass -File root.ps1
```

详细文档见 `docs/USAGE.zh-CN.md`；文件清单见 `docs/FILE_MAP.zh-CN.md`。
