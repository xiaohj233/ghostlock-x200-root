# GhostLock-X200 v1.3.1

## 本版说明

- v1.3.1 为**发布机制修复版**：功能代码与 v1.3.0 完全一致，v1.3.0 已包含
  多机型通用管线、离线恢复、P0 自动获取、KMI 自动重打、win_offs 去
  vmlinux-to-elf 依赖等全部能力，详见 `release_notes_v1.3.0.md`。
- 本版仅列出**相对 v1.3.0 真正新增**的内容，不再重复罗列 v1.3.0 已发布的修复项。

## 新增（相对 v1.3.0）

- **同版本号禁止覆盖**：`publish.py` 检测到 tag / GitHub Release 已存在时
  直接拒绝并提示递增版本号（不再删除旧资产重建），彻底杜绝"同版本号反复
  重新打包发布、旧下载者无法感知更新"的问题。
- **版本标识统一 v1.3.1**：root.ps1 启动横幅与异常诊断清单、README、
  FILE_MAP 中的版本号同步更新。

## 使用

```powershell
# 唯一入口（Windows）：
run_root.bat
# 或：powershell -ExecutionPolicy Bypass -File root.ps1

# 一键发布 (重编二进制 + 打包 + 校验 + 提交推送 + GitHub Release):
python publish.py [--version v1.3.1] [--dry-run]
```

详细文档见 `docs/USAGE.zh-CN.md`；文件清单见 `docs/FILE_MAP.zh-CN.md`。
