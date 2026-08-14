# GhostLock-X200 v1.3.4.1

## 修复

- **修复编码错误**: v1.3.4 打包时 `root.ps1` 丢失 UTF-8 BOM, 导致 Windows PowerShell
  5.1 (`run_root.bat` 调用的 `powershell.exe`) 按 ANSI 误读中文注释/字符串,
  双击 `run_root.bat` 直接报 PowerShell 解析错误 (`Missing closing ')'` / `||` 等)。
  v1.3.4.1 已补回 BOM, 并给发布流程增加 BOM 校验, 防止再次发生。

## 说明

- 二进制与 v1.3.4 完全一致 (glt_esync / ksud / w2host, 均已实测通过), 本次仅修复编码问题。
