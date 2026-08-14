# GhostLock-X200 v1.3.5-beta1 (本地测试版, 不发 GitHub)

## 背景

用户设备在 STAGE5 CAPSROOT 写 cred 时内核 panic/watchdog (v1.3.4.1)。
本版为 STAGE5 崩溃的**根因修复**本地测试版, 开发机已通过 4 次干净重启完整链路
(4/4 成功, 无 panic / watchdog / 残留进程)。请完整跑一遍并回传窗口截图 + 诊断包 zip。

## 根因 (pstore 实证)

STAGE5 崩溃栈 (多次一致):

    _raw_spin_trylock+0x1c  (读垃圾地址)
    rt_mutex_adjust_prio_chain+0x130
    remove_waiter+0x20c
    rt_mutex_cleanup_proxy_lock+0x50
    futex_lock_pi+0x288

两个叠加的崩溃源:

1. **写链完成后的二次链走**: glt 在 slide 写原语执行后继续跑 main.c 默认路径的
   `run_main_route_threads()` (fops 线程), 其 consumer 的 futex_lock_pi 不受
   GL_NO_LOCKPI 保护, 会第二次链走命中已被 pselect 覆盖的假 waiter ->
   读垃圾 waiter->lock -> panic。**修复: STAGE1/2/5 统一加 GL_SLIDE_ONLY=1**
   (写链完成后 glt 立即退出, 不再跑 fops 线程)。
2. **GL_FPAD=24 引入的覆盖漂移**: alloca(24) 在 aarch64 16B 对齐后实际占 32B,
   使 rt_waiter 相对 pselect fd_set 漂移约 4 个 word, lock 字段读到 fd_set 之外
   (words 表最多覆盖 15 个 word) -> _raw_spin_trylock(垃圾)。**修复: 恢复
   GL_FPAD=0 (官方 Δ=0 对齐)** + slide.c words 表加宽/安全化兜底漂移。

## 本版改动

- **STAGE1/2/5 加 GL_SLIDE_ONLY=1**: 写链完成后立即退出, 消除二次链走 (根因 1)。
- **GL_FPAD=24 -> 0**: 消除 4-word 覆盖漂移 (根因 2), 与 pselect.json 官方推导一致。
- **slide.c words 表安全化**: words[4]/[11..14] 填 GL_LOCK (内核 bss 全零区),
  words[10]=init_task 保留 (命中必需)。漂移 ±1~±4 时 lock/tree 字段读到零区
  -> 安全 miss 不崩, ±0 时正常命中。
- **逃生门 (防残留/watchdog)**: child 设 alarm(15) + PR_SET_PDEATHSIG(SIGKILL);
  child 主线程 route_done 等待超时 (10s); parent 读子进程结果改 select 超时
  (15s) + SIGKILL child; consumer 自旋加上限。写原语命中/卡死后进程必然退出,
  不再残留占 CPU (此前 watchdog 抓 glt 残留 CPU7 R running)。
- **STAGE5 WRITE 标记 sync 落盘**: panic 重启会丢 page cache (F2FS 回滚),
  崩溃后仍可拿到最后写参数。
- **STAGE3.4 输出 capsym 符号名**: 便于定位写链目标。
- **诊断文案**: 明确要求同时发送诊断包 zip。
- **诊断包收集新增 capsroot_* 文件**。
- **glt 二进制重编**: 含以上 slide.c 修复 + configfs 备用路径 (GL_CRED, 未启用)。

## 开发机实测 (vivo X200 PD2415, b57af212129c)

干净重启 -> 完整链路 4/4 成功 (16:45 / 16:52 / 16:58 / 17:05):

- STAGE1/2 permissive+kptr OK
- STAGE5 R1 安全 miss -> R2 CAPSROOT 命中 (w2host capset 提权)
- STAGE6 kernelsu + permissive_restore + clear_vr_tag Live
- STAGE7 Permissive + KSU 32525 + 网络通
- STAGE8 su uid=0(root) + ksud manager 注册

## 已知情况

- 写链仍为概率性时序原语, 但崩路径已被上述两项根因修复消除; 残余 miss
  (安全不崩) 由 ROUND 换 candidate 重试覆盖 (R2 命中率 100%)。
- 一次机会, 重启即失败 (无自动重试)。若仍崩溃, 请回传诊断包 zip (含
  pstore 关键行与 WRITE 标记), 用于最终定位。
