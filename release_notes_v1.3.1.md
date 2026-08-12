# GhostLock-X200 v1.3.1

## 本版说明

- v1.3.1 为 v1.3.0 的**修复版**（版本号递增发布，不再覆盖同版本资产；
  已下载 v1.3.0 的用户请改用本版，以获得以下修复）。
- 功能全貌见 `release_notes_v1.3.0.md`；本版相对 v1.3.0 的修复如下。

## 修复（相对 v1.3.0）

- **prebuilt 二进制与源码同步重编**：发布流程改为每次用当前源码重编
  `prebuilt/glt_esync` / `prebuilt/w2host`（WSL kali NDK），不再沿用旧二进制；
  源码含 STAGE2（kptr 写）watchdog 修复（words[0] 必须 RED 防
  `____rb_erase_color` 在垃圾树上旋转），干净状态真机验证：STAGE1→2 不再
  watchdog，STAGE2 miss 安全重试，全链路 ALL STAGES PASS 且设备稳定。
- **detect-p0 多设备去重**：USB + 无线同一物理设备时按 ro.serialno 自动选用，
  主链成功后的自动 P0 获取不再失败（实测输出 0x80000000）。
- **run_root.bat CRLF + ASCII 注释**：修复 LF 行尾 + UTF-8 中文注释导致 cmd
  把注释碎片当命令执行（`'閫夊弬鏁伴€忎紶' is not recognized`）。
- **多设备自动选择**：同一物理设备 USB + 无线双连接时自动选用 USB，
  不再误报"检测到多台设备"退出。
- **发布机制**：新增 `publish.py` 一键发布（重编二进制 → 打包 → 校验 →
  提交推送 → GitHub Release）；**同版本号禁止覆盖**（已存在则报错提示递增版本号）。

## 使用

```powershell
# 唯一入口（Windows）：
run_root.bat
# 或：powershell -ExecutionPolicy Bypass -File root.ps1

# 一键发布 (重编二进制 + 打包 + 推送 + GitHub Release):
python publish.py [--version v1.3.1] [--dry-run]
```

详细文档见 `docs/USAGE.zh-CN.md`；文件清单见 `docs/FILE_MAP.zh-CN.md`。
