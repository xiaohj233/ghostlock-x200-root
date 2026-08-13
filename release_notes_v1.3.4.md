# GhostLock-X200 v1.3.4

## 本版说明

- v1.3.4 为 v1.3.3 的**稳定性修复版**，功能全貌见 `release_notes_v1.3.0.md`；
  本版仅列出相对 v1.3.3 的变化（含两轮修复：manager "获取 root 失败"+UI 空白、
  manager 模块页/超级用户页永久转圈）。

## 修复 1（对比 v1.3.3）：manager "获取 root 失败" + UI 空白

- **根因**：vivo `vr.ko` 反 root 模块 hook `commit_creds` 给提权进程打标记，
  并在 `sys_exit`（syscall trace 路径）杀掉"非 root→root"转换的进程 →
  KernelSU manager 提权瞬间被杀，表现为"获取 root 失败"+ 界面空白。
- **修复**：新增内核模块 `clear_vr_tag.ko`（GPL-2.0，源码随包），kretprobe
  `commit_creds`：仅在真正的非 root→root 提权时清除 `task+0x06`/`task+0x2c`
  标记与 `TIF_SYSCALL_TRACEPOINT` 位（root→root、非 root→非 root 不动，
  避免破坏 KernelSU 对 app 链的系统调用 hook）。主链新增 **STAGE6.5** 在
  kernelsu 加载后立即 insmod 该模块（`cc_addr` 取当前 boot kallsyms 的
  `commit_creds` 地址）。
- **偏移提取工具**：新增 `tools/offset_tools/extract_vr_from_img.py`
  （从固件镜像提取 vr.ko）与 `extract_vr_offsets.py`（逆向提取对抗偏移），
  产出 `tools/scripts/vr_offsets.json`（内置 b57 实测值，其他机型可自动重算）。

## 修复 2（对比 v1.3.3）：manager 模块页/超级用户页永久转圈

- **根因 1**：KernelSU sucompat 把所有 `su` 调用重定向执行 `/data/adb/ksud`。
  该文件缺失/损坏时（首次装机 / `ksud install` 半途失败），全部 `su` 失败
  （`su: inaccessible or not found`）→ 模块页/超级用户页永久转圈。
  - 修复：新增 **STAGE6.1**，加载 kernelsu 后立即校验 `/data/adb/ksud` 为
    完整 ELF，缺失/损坏自动修复（su 可用走 su，su 不可用回退 rootcmd），
    先于一切 su 使用。
- **根因 2**：manager 未注册（缺 `ksud debug get-sign`），内核不识别
  manager，其自身 su 被降级为非 root profile（实测 uid=2）→ 页面永远
  拿不到 root。
  - 修复：**STAGE8** 自动执行 `ksud debug get-sign`（内核据此识别 manager）。
- **根因 3**：STAGE6.5 原先经 rootcmd socket 加载 clear_vr_tag，而 kernelsu
  加载后会阻断该 socket → 对抗模块加载失败。
  - 修复：STAGE6.5 改用 `su -c insmod`，加载结果严格门禁（FAIL 即报错）。

## 其他变化（对比 v1.3.3）

- **panic 诊断增强**：失败时窗口内直接显示诊断摘要与"失败定位"（最后 STAGE
  状态）+ 主链输出尾部，截图即可定位，无需解包 zip。
- **失败路径加固**：`-WinOffsPath` 传入不存在的偏移文件时立即报
  `WIN OFFS MISSING` 并以非零码退出（此前静默空偏移继续运行）。
- **敏感信息清理**：root.ps1 注释中的设备示例序列号、`vr_offsets.json`
  中的本机构建路径替换为占位符。
- **版本号统一 v1.3.4**：README / root.ps1 横幅与诊断清单 / FILE_MAP 同步；
  v1.3.3 release notes 归档至 `docs/release_notes/`。

## 验证

- 真机连续两轮"重启 → 完整主链 → manager 三页面"全部正常：
  `ALL STAGES PASS`、manager 主页/模块页/超级用户页均正常加载
  （无 EACCES、root shell 正常存活）。
- 失败分支实测：`-WinOffsPath` 坏路径、无设备场景均以正确非零码退出并给出
  对应报错/诊断包。

## 已知问题（排查提示）

- 若个别设备模块页/超级用户页仍转圈，检查
  `/data/user_de/0/me.weishu.kernelsu/cache/main.jar` 是否异常只读
  （`ls -l` 显示 `r--r--r--`）。删除该文件后重开 manager 即可（app 会自动重新解压）。

## 使用

```powershell
# 唯一入口（Windows）：
run_root.bat
# 或：powershell -ExecutionPolicy Bypass -File root.ps1
```

详细文档见 `docs/USAGE.zh-CN.md`；文件清单见 `docs/FILE_MAP.zh-CN.md`。
