# GhostLock-X200 v1.3.5-beta2 (本地测试版, 不发 GitHub)

## 背景

beta1 在用户设备 (PD2415, b57af212129c) 上提权/kernelsu 模块加载全部成功,
但完成后 KernelSU manager 显示"未安装", 退出重开依旧。本版为该问题的
**根因修复**本地测试版, 修复后应能: 主链跑完 -> 打开 manager 显示已安装 ->
模块页/超级用户页正常 -> root 可授权。

## 根因 (日志 + KernelSU 3.2.5 源码定位)

用户日志失败链 (STAGE6.1 repair failed -> su 全灭 -> clear_vr_tag 未加载 ->
STAGE8 跳过 -> manager "未安装"):

1. **su 可用 ⟺ /data/adb/ksud 存在**: KernelSU sucompat (kernel/feature/sucompat.c)
   把所有 su 调用重定向执行 /data/adb/ksud; 该文件缺失时回退执行真实
   /system/bin/su (设备不存在) -> ENOENT -> "su: inaccessible or not found"。
2. **rootcmd 回退必然已死**: 旧 STAGE6.1 的 repair 走 rootcmd
   (CHMOD 777 /data/adb + adb cp), 但 STAGE6.1 在 kernelsu INSMOD 之后执行,
   而 kernelsu 加载会 setenforce(true) (core/init.c) 并阻断 rootcmd socket
   (STAGE6.5 早已因此改用 su -c)。-> "需要回退 rootcmd 时, rootcmd 已死"。
3. **假 PASS 掩盖**: STAGE7 门禁只查 模块 Live + ksud version + ping,
   从不验证 su/ksud 真身 -> 主链报 ALL STAGES PASS, 实际 KSU userspace 全缺。
4. **manager 判定**: manager 通过扫描 /proc/self/fd 找 [ksu_driver] fd
   (由 ksud 以 root 调 reboot(magic) 注入); ksud daemon 未启动 -> 无 fd ->
   Natives.version=0 -> UI 显示 "Not installed" (未安装)。

## 本版改动 (仅 tools/scripts/root_full_permissive_restore.ps1)

- **新增 STAGE6.0a: clear_vr_tag 前置加载**。permissive_restore INSMOD 的
  commit_creds 提权进程会被 vr.ko 在 sys_exit 杀 (实证: INSMOD socket 返回空,
  后续代码无机会执行), 先加载 clear_vr_tag (kretprobe 清 vr 标记) 后提权进程
  存活 -> root 窗口内可完成 ksud 落位。
- **新增 STAGE6.0: ksud 落位 (root 窗口 + KSETUP)**。w2host INSMOD 分支在
  init_module 成功后 (进程已被 permissive_restore commit_creds 提为 uid0+全caps)
  直接落位 /data/adb/ksud (W2_KSETUP_SRC 注入) 并写标记文件校验
  size=4556352 mode=755。不依赖 CAPSROOT 的随机 caps (cap_permitted = capsym
  KASLR 符号地址低 32 位, 缺 CAP_DAC_OVERRIDE 时 rootcmd 文件操作全 EACCES,
  回归实测), 也不依赖 uid 2000 的 adb cp。
- **STAGE6.1 改为 su 首验**: kernelsu 加载后验证 su -> /data/adb/ksud ELF,
  失败打印完整诊断 (rootcmd STAT + su -c id), 不静默。
- **STAGE7 门禁增强**: 追加硬门禁 `su -c id` 必须 uid=0(root) 且
  /data/adb/ksud 头 4 字节为 7f454c46, 任一失败 exit 1 (杜绝假 PASS)。
- **w2host 重编**: 新增 KSETUP (INSMOD 成功后 root 窗口内落位 + 标记文件)。
- **版本号**: root.ps1 / manifest 统一 v1.3.5-beta2。

## 验证要求 (用户实测)

重启设备 -> 完整跑一遍 -> 完成后打开 KernelSU manager:

- 首页显示已安装 (Working, 版本 32525) 而非 "Not installed";
- 模块页 / 超级用户页不再转圈; adb shell su -c id 返回 uid=0(root)。

若仍失败, 请务必发送**诊断包 zip** (窗口内路径 log\ghostlock_diag_*.zip),
窗口截图不足以定位。

## 已知情况

- 写链仍为概率性时序原语 (R2 命中率 100%), 本版不涉及 STAGE1-5 改动。
- 一次机会, 重启即失败 (无自动重试); 若崩溃请回传诊断包 zip。
