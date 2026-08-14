# GhostLock-X200 v1.3.5 更新日志

与 v1.3.4.1 相比:

## 修复

- **STAGE5 写链 panic 根因修复**: 写链完成后立即退出 (GL_SLIDE_ONLY), 消除二次链走;
  恢复官方对齐 (GL_FPAD 24→0) 消除 fd_set 覆盖漂移; 覆盖漂移时锁/树字段读零区
  (words 表安全化) 安全 miss 而非 panic; 新增逃生门 (alarm/超时/强制退出),
  卡死进程不再残留占 CPU 触发 watchdog。
- **KernelSU su 全灭修复**: ksud 在 root 窗口内落位 /data/adb (STAGE6.0),
  kernelsu 加载前就位; /data/adb 强制 0755, 修复第二次及以后运行 su 失效
  ("su: inaccessible or not found"); STAGE6.1/STAGE7 真实校验 su 与 ksud,
  杜绝假 PASS。
- **vr.ko 反 root 对抗前置**: clear_vr_tag 在提权进程创建前加载, 防止
  KernelSU 提权进程被杀 (manager "获取 root 失败"/页面异常)。
- **极端负载 panic 防护**: STAGE4 写前静默门, 设备负载 (loadavg) 过高时
  中止运行并提示, 不再冒险写入 (STAGE5 写链在极端负载下有 panic 风险)。

## 新增

- **STAGE0 内核匹配门禁**: 设备内核与机型偏移不匹配时, 在第一次内核写之前退出。
- **非 b57 机型 glt 门禁**: 禁止使用 b57 编译的二进制跨内核强跑; 非 b57 机型
  必须使用本机型编译产物, 缺失时自动编译 (失败即终止, 不再提供风险自担选项)。
- **NDK 自动下载确认**: 无可用 NDK 时, 下载前明确提示体积 (约 1.1GB) 与保存位置。
- **vr.ko 偏移跨机型化**: 优先使用机型模块自带 vr_offsets.json。
- **w2host 轮询降负载**: 每轮额外 1ms 睡眠, 降低写链窗口期自干扰。

## 已知情况

- STAGE5 写链为概率性时序原语: 设备繁忙时首轮可能 miss (安全), 由后续轮次命中;
  设备负载过高时 (loadavg≥20) 直接中止, 不重启不 panic。
- 仅 vivo X200 PD2415 (b57) 真机适配; 其他机型需自行生成模块并编译本机型 glt。
- 在线卸载内核模块 (rmmod) 会触发 kernel panic; 工具不提供在线卸载, 重启设备即清除。
