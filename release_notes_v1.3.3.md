# GhostLock-X200 v1.3.3

## 本版说明

- v1.3.3 为 v1.3.2 的**稳定性修复版**，功能全貌见 `release_notes_v1.3.0.md`；
  本版仅列出相对 v1.3.2 的修复。

## 修复（相对 v1.3.2）

- **STAGE4/5 cred 候选质量修复（核心）**：
  - 根因：w2host 采样候选采用"3 轮交集 + **无条件并集**"，单轮出现的
    候选（已释放/临时/非本进程 cred）会混入 → STAGE5 盲写该假候选破坏
    slab 对象 → 下一轮设备 panic/watchdog（10:04 实机实证：ROUND 1 全 0、
    ROUND 2 假候选 miss、ROUND 3 设备 panic）。
  - 修复：候选改为"3 轮交集 ∪ 至少 2/3 轮出现的候选"，**单轮候选丢弃**；
    STAGE5 写目标均为稳定 cred，miss 时不再破坏内核，多轮重试安全。
  - 验证：真机连续 3 次 ALL STAGES PASS（1 次 ROUND 2 成功、2 次 ROUND 1
    一次命中），修复前同环境下 ROUND 3 必 panic。
- **版本号同步 v1.3.3**：root.ps1 启动横幅与诊断清单此前仍显示 v1.3.1，
  现已统一（README / FILE_MAP 同步）。

## 使用

```powershell
# 唯一入口（Windows）：
run_root.bat
# 或：powershell -ExecutionPolicy Bypass -File root.ps1
```

详细文档见 `docs/USAGE.zh-CN.md`；文件清单见 `docs/FILE_MAP.zh-CN.md`。
