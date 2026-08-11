# GhostLock-X200 v1.3.0

## 本版定位

- 在 v1.1.0（X200 b57 参考实现 + 异常重启诊断）基础上，完成**多机型通用化**：
  任意 vivo/iQOO（及同内核族设备）提供 boot.img / 全量包 zip / payload.bin /
  kernel.raw / kernel.elf 素材，即可**全自动**生成可分享的机型模块并尝试 root，
  无需已 root 设备、无需 vmlinux-to-elf、无需手动编译 exploit。
- 机型参数与偏移产物收敛为可分享模块（`devices/<机型名>/`），他人导入后
  **同内核自动精确命中**，零提取直接使用。

## 新增

### 多机型通用管线（v1.2 - v1.4）
- **机型模块化 + 可分享**：`devices/<机型名>/` 自包含 device.json + 偏移产物 +
  manifest（SHA256 校验）；设备在线按 `/proc/version` 自动匹配（精确 / 同族 /
  未收录三态）；未收录机型自动提取并生成新模块，可打包分享。
- **机型可行性预检**：素材选择后输出 推荐 / 可尝试 / 不推荐 + 逐项原因，
  覆盖 init_boot 误选（kernel_size=0）、内核族、SoC、PANIC_ON_OOPS 等；
  MTK 未知族明确提示不推荐（附社区失败证据）。
- **离线恢复（无设备）**：仅凭素材离线恢复 kallsyms + BTF（6.1 / 6.6 / 6.12
  分支），无设备也能生成全部偏移与 target header。
- **pselect 栈布局自动推导**：反汇编 pselect/futex 调用链自动得出
  `PSELECT_WAITER_WORD_SHIFT`（b57 实测 = 0，与真机一致），不再手动固化。
- **P0 物理常量自动获取**：root /proc/iomem → 设备 devicetree（非 root）→
  素材 DTB → 待填，四级自动填充链；含 6 项反向校验。

### 新机型流程闭环（v1.5 - v1.6）
- **win_offs 去 vmlinux-to-elf 依赖**：内核 Image 直反汇编（capstone + 离线
  kallsyms）复现偏移，与 ELF 路径产物全等；vmlinux-to-elf 降级为可选。
- **新机型流程 package 主导**：素材 → 可行性预检 → 自动提取全套 → 机型模块，
  不再被 vmlinux-to-elf 缺失卡死；`task_cred_off` 由素材 BTF 自动推导
  （不同构建不同，如 0x820 / 0x8c8）。
- **KMI 自动触发**：模块生成后自动按模块 `kernel_release` 重打
  kernelsu.ko / permissive_restore.ko 的 vermagic；`-KernelRelease` 保留手动覆盖。
- **非 b57 prebuilt 门禁**：主链优先使用机型模块自带产物；非 b57 且无产物时
  询问后默认不跑（避免 b57 预编译偏移硬编码导致的失败/panic），提示按机型重编译。

### 编译自动化（v1.7）
- **exploit 自动编译**：非 b57 门禁处询问后自动用 WSL kali NDK（或自动下载
  Android NDK r28）按机型模块 target.h 编译 `glt_esync` 并放入模块；与历史
  构建同链（重编 w2host 与仓库产物 SHA256 全等）。
- **w2host 运行时自适应澄清**：w2host 采样窗口/候选范围已运行时注入
  （W2_CRED_IPS / W2_CAND_MIN / W2_DIRECT_END 等），无需按机型重编译，
  直接复用仓库 prebuilt。

## 修复

- **vivo boot 头 page_size=0**：内核段定位失败导致 `内核缺少 arm64 Image magic`
  （unpack_boot.py / offline / winoffs-image 均修复，真实 OTA boot.img 验证）。
- **裸内核 Image（.img 无 ANDROID! 头）素材误判**为 boot.img 导致解包失败。
- **detect-p0 低端 System RAM 小块**导致 phys_offset 误算为 0x0（改为基于内核
  加载所在 RAM 块推导）。
- **P0 待填模块导入即报错**：`load_profile` 允许 P0 null（待填态），模块分享
  闭环不再中断。
- **--help / 未知子命令** 报 TypeError（改友好报错）。
- **重复参数 -KsuKoPath** 传递导致 PowerShell 绑定失败。

## 已知边界

- 内核模块（kernelsu / permissive_restore）真正重编仍需同构建内核源码
  （modversions ABI）；vermagic 重打已自动，非同构建 insmod 可能失败。
- 仅 X200 (PD2415) b57 真机完整验证（STAGE1-7 全通过）；X200s 同内核
  （内核 SHA256 全等）偏移交叉验证一致，但未实体机实测；其余机型为素材级
  自动适配，需实体机验证。
- 6.1 / 6.12 分支离线恢复实现完成，待对应内核素材实体验证。

## 使用

```powershell
# 唯一入口（Windows）：
run_root.bat
# 或：powershell -ExecutionPolicy Bypass -File root.ps1

# 生成/分享/导入机型模块：
python tools\offset_tools\offsets_auto.py package C:\path\boot.img --out devices\my_device
python tools\offset_tools\offsets_auto.py verify-device my_device
```

详细文档见 `docs/USAGE.zh-CN.md`；文件清单见 `docs/FILE_MAP.zh-CN.md`。
