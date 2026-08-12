# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
# ============================================================
# root.ps1 - GhostLock-X200 一键 Root (小白友好 / GUI 引导)
#
# 功能:
#   1. 自动检测设备 + 内核 build
#   2. 首次 / build 不匹配时: 自动解包并重新生成偏移 (win_offs)
#      - 支持输入: 全量包 zip / payload.bin / boot.img / kernel.raw / kernel.elf
#      - 自动识别文件类型, 自动调用对应工具链
#   3. 然后调用 tools/scripts/root_full_permissive_restore.ps1 完成 root
#   4. -Force: 跳过 build 检测, 强制用随包 b57 偏移直接跑 (风险自担)
#   5. -SkipPermissiveRestore: 不加载 permissive_restore.ko (enforcing 保持, 网络可能断)
#
# 用法:
#   powershell -ExecutionPolicy Bypass -File root.ps1
#   powershell -ExecutionPolicy Bypass -File root.ps1 -Force
#   powershell -ExecutionPolicy Bypass -File root.ps1 -AssetPath C:\path\boot.img
#   powershell -ExecutionPolicy Bypass -File root.ps1 -SkipPermissiveRestore
#   powershell -ExecutionPolicy Bypass -File root.ps1 -SkipDeps   # 不自动下载任何依赖
#   powershell -ExecutionPolicy Bypass -File root.ps1 -NoLog       # 不写日志 (默认每次自动写 %TEMP%\ghostlock_root_<时间戳>.log)
#   powershell -ExecutionPolicy Bypass -File root.ps1 -DepsInPackage  # 依赖下载到项目根目录 (v1.1.0 起为默认)
# 自动依赖下载 (开箱即用, 默认写入项目根目录 platform-tools/、payload-dumper-go/ 等,
#   包内自包含; 项目根不可写时自动回退 %LOCALAPPDATA%\GhostLock-X200\deps 旧位置):
#   adb (platform-tools 官方) / Python 依赖 (pip) / payload-dumper-go (GitHub release)
#   / vmlinux-to-elf (pip, GPL-3.0) — 均在缺失且联网时自动获取; -SkipDeps 关闭.
# 异常重启诊断 (默认开启): 主链失败后自动采集诊断日志 (检测到重启则含 pstore/AEE 等
#   panic 产物), 打包 ghostlock_diag_<时间戳>.zip 并给出指引; -NoPanicDiag 关闭.
# ============================================================
param(
  [switch]$Force,          # 跳过 build 检测, 强制用随包 b57 偏移直接跑
  [string]$AssetPath,      # 指定素材文件 (zip/payload.bin/boot.img/kernel.raw/kernel.elf); 缺省弹文件选择框
  [string]$AdbPath,        # 透传: adb.exe 位置
  [string]$Serial,         # 透传: 设备序列号
  [string]$KsuKoPath,      # 透传: 用户 kernelsu.ko
  [switch]$SkipPermissiveRestore,  # 透传: 不加载 permissive_restore.ko
  [string]$Python,         # python 解释器 (缺省自动探测)
  [switch]$SkipDeps,       # 不自动下载依赖 (离线/审查场景)
  [string]$DepsDir,        # 依赖下载目录 (默认项目根目录; 可指定其他目录)
  [switch]$DepsInPackage,  # 依赖下载到项目根目录 (v1.1.0 起为默认行为, 保留兼容)
  [switch]$NoLog,          # 不写日志 (默认每次自动写 %TEMP%\ghostlock_root_<时间戳>.log)
  [string]$LogPath,        # 日志文件路径 (默认 <包根>\log\ghostlock_root_<时间戳>.log)
  [switch]$NoPanicDiag,    # 主链失败后不自动采集 panic 诊断日志 (默认开启)
  [string]$Profile,        # 机型 profile (默认 tools/offset_tools/profiles/x200_b57.json; 新机型: 复制改名填写)
  [string]$KernelRelease   # 目标内核完整 UTS_RELEASE (如 /proc/version 第 3 字段); 与 profile 不同时自动重打 ko vermagic
)
$ErrorActionPreference = 'SilentlyContinue'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkgRoot   = $scriptDir
# 智能 adb 定位 (共用工具: 显式 > 环境 > PATH > 常见位置 > 有界搜索, 均校验可用性)
if (Test-Path (Join-Path $pkgRoot "tools\scripts\find_adb.ps1")) {
  . (Join-Path $pkgRoot "tools\scripts\find_adb.ps1")
} else {
  # 容错: 包内缺 find_adb.ps1 时退化为旧逻辑 (不因缺文件直接报错)
  function Test-AdbWorking { param([string]$Path) return [bool]$Path }
  function Get-AdbPath {
    param([string]$Preferred)
    if ($Preferred) { return $Preferred }
    if ($env:ANDROID_ADB) { return $env:ANDROID_ADB }
    return (Get-Command adb -ErrorAction SilentlyContinue).Source
  }
}
$KERNEL_ELF_PAT  = $null   # 本次生成/找到的 kernel ELF
$GEN_WIN_OFFS    = $null   # 本次生成的 win_offs json

# ---------- 机型模块 (v1.4: devices/ 可分享模块, 自动匹配) ----------
$ProfilePath = $Profile
if (-not $ProfilePath) { $ProfilePath = Join-Path $pkgRoot "devices\x200_b57\device.json" }
$ProfileInfo = @{}
try {
  if (Test-Path -LiteralPath $ProfilePath) {
    $ProfileInfo = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json
  } else {
    SayWarn "机型模块不存在: $ProfilePath (缺省 devices/x200_b57; 未收录机型将自动生成)"
  }
} catch { SayWarn "机型模块读取失败: $_" }

# ---------- 日志 (默认开启: 统一写入 <包根>\log\ 文件夹; -NoLog 关闭) ----------
$LOG_FILE = $null
if (-not $NoLog) {
  if (-not $LogPath) { $LogPath = Join-Path $pkgRoot ("log\ghostlock_root_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log") }
  try {
    $logDir = Split-Path $LogPath -Parent
    if (-not $logDir) { $logDir = (Get-Location).Path }
    New-Item -ItemType Directory -Force -Path $logDir -ErrorAction Stop | Out-Null
    $LOG_FILE = (Resolve-Path $logDir).Path + "\" + (Split-Path $LogPath -Leaf)
    "" | Out-File -FilePath $LOG_FILE -Encoding utf8 -ErrorAction Stop
  } catch {
    # log 目录不可写时回退 %TEMP%
    $LOG_FILE = $null
    try {
      $tmpLog = Join-Path $env:TEMP ("ghostlock_root_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
      New-Item -ItemType Directory -Force -Path (Split-Path $tmpLog) -ErrorAction Stop | Out-Null
      "" | Out-File -FilePath $tmpLog -Encoding utf8 -ErrorAction Stop
      $LOG_FILE = $tmpLog
    } catch { $LOG_FILE = $null }
  }
}

function Log-Raw([string]$m) {
  if ($LOG_FILE) { ("[" + (Get-Date -Format "HH:mm:ss") + "] " + $m) | Out-File -FilePath $LOG_FILE -Encoding utf8 -Append }
}

function Show-Tail([string]$text, [int]$n = 20) {
  @($text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last $n) | ForEach-Object { SayErr "  $_" }
}

function Say($m) { Write-Host $m; Log-Raw $m }
function SayWarn($m) { Write-Host "[!] $m" -ForegroundColor Yellow; Log-Raw "[!] $m" }
function SayErr($m) { Write-Host "[X] $m" -ForegroundColor Red; Log-Raw "[X] $m" }
function SayOk($m) { Write-Host "[OK] $m" -ForegroundColor Green; Log-Raw "[OK] $m" }

if ($LOG_FILE) { SayOk "日志文件: $LOG_FILE" }

# ---------- GUI 文件选择 (小白友好) ----------
function Pick-File {
  param([string]$Title, [string]$Filter)
  try {
    Add-Type -AssemblyName System.Windows.Forms
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = $Title
    $dlg.Filter = $Filter
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
      return $dlg.FileName
    }
  } catch { }
  return $null
}

function Choose-Asset {
  # 优先 -AssetPath, 否则弹窗
  if ($AssetPath) {
    if (Test-Path $AssetPath) { return (Resolve-Path $AssetPath).Path }
    SayErr "AssetPath 不存在: $AssetPath"; exit 1
  }
  $f = Pick-File "请选择素材文件 (全量包 zip / payload.bin / boot.img / kernel.raw / kernel.elf)" "All files (*.*)|*.*"
  if (-not $f) { SayErr "未选择文件, 退出"; exit 1 }
  return $f
}

# ---------- 文件类型识别 ----------
function Get-FileKind {
  param([string]$Path)
  $ext = [System.IO.Path]::GetExtension($Path).ToLower()
  $head = ""
  try {
    $fs = [System.IO.File]::OpenRead($Path)
    $b = New-Object byte[] 8
    $fs.Read($b, 0, 8) | Out-Null
    $fs.Close()
    $head = [System.Text.Encoding]::ASCII.GetString($b)
  } catch { }
  if ($ext -eq ".zip") { return "fullzip" }
  if ($head -like "CrAU*") { return "payload" }
  if ($head -like "ANDROID!*") { return "bootimg" }
  if ($head -like "`x7fELF*") { return "kernel_elf" }
  # 无魔数但扩展名提示
  if ($ext -eq ".img") {
    # 裸内核 Image (.img 无 ANDROID! 头): 探测 arm64 Image magic / 压缩魔数
    try {
      $fs = [System.IO.File]::OpenRead($Path)
      $b = New-Object byte[] 0x40
      $fs.Read($b, 0, 0x40) | Out-Null
      $fs.Close()
      $magic38 = [System.Text.Encoding]::ASCII.GetString($b, 0x38, 4)
      $lz4 = ($b[0] -eq 0x02 -and $b[1] -eq 0x21 -and $b[2] -eq 0x4c -and $b[3] -eq 0x18)
      $gzip = ($b[0] -eq 0x1f -and $b[1] -eq 0x8b)
      $xz = ($b[0] -eq 0xfd -and $b[1] -eq 0x37 -and $b[2] -eq 0x7a -and $b[3] -eq 0x58)
      if ($magic38 -eq "ARMd" -or $lz4 -or $gzip -or $xz) { return "kernel_raw" }
    } catch { }
    return "bootimg"
  }
  if ($ext -eq ".bin") { return "payload" }
  if ($ext -eq ".elf") { return "kernel_elf" }
  if ($ext -eq ".raw") { return "kernel_raw" }
  return "unknown"
}

# ---------- 机型模块自动匹配 (v1.4): 按 /proc/version 扫描 devices/ ----------
function Match-DeviceModule {
  param([string]$VerLine)
  $devRoot = Join-Path $pkgRoot "devices"
  if (-not (Test-Path -LiteralPath $devRoot)) { return $null }
  $familyHit = $null
  foreach ($d in @(Get-ChildItem -LiteralPath $devRoot -Directory -ErrorAction SilentlyContinue)) {
    $djp = Join-Path $d.FullName "device.json"
    if (-not (Test-Path -LiteralPath $djp)) { continue }
    try { $dj = Get-Content -LiteralPath $djp -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
    if ($dj.kernel_release -and $VerLine -like ("*" + $dj.kernel_release + "*")) {
      return @{ path = $djp; level = "exact"; device = $dj }
    }
    if (-not $familyHit -and $dj.family -and $VerLine -like ("*" + $dj.family + "*")) {
      $familyHit = @{ path = $djp; level = "family"; device = $dj }
    }
  }
  return $familyHit
}

# ---------- ko vermagic 检测 (v1.6: KMI 自动触发用) ----------
function Get-KoVermagic {
  param([string]$Path)
  try {
    $b = [System.IO.File]::ReadAllBytes($Path)
    $txt = [System.Text.Encoding]::ASCII.GetString($b)
    $m = [regex]::Match($txt, "vermagic=([^\x00]*)")
    if ($m.Success) { return $m.Groups[1].Value }
  } catch { }
  return ""
}

# ---------- NDK 探测 (v1.7: exploit 自动编译) ----------
function Find-NDK {
  # 返回 @{ type="win"; clang=<cmd> } | @{ type="wsl"; ndk_bin=<kali bin> } | $null
  # 1) Windows NDK: 环境变量 / 常见 SDK ndk / 项目根 ndk
  foreach ($envvar in @("ANDROID_NDK_HOME", "ANDROID_NDK", "NDK_HOME")) {
    $ev = [Environment]::GetEnvironmentVariable($envvar)
    if ($ev -and (Test-Path -LiteralPath $ev)) {
      $cand = Join-Path $ev "toolchains\llvm\prebuilt"
      if (Test-Path -LiteralPath $cand) {
        foreach ($h in @(Get-ChildItem -LiteralPath $cand -Directory -ErrorAction SilentlyContinue)) {
          $c = Join-Path $h.FullName "bin\aarch64-linux-android28-clang.cmd"
          if (Test-Path -LiteralPath $c) { return @{ type = "win"; clang = $c } }
          $ce = Join-Path $h.FullName "bin\aarch64-linux-android28-clang.exe"
          if (Test-Path -LiteralPath $ce) { return @{ type = "win"; clang = $ce } }
        }
      }
    }
  }
  foreach ($base in @((Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk"), "C:\Android\ndk",
                      (Join-Path $pkgRoot "ndk"))) {
    if (Test-Path -LiteralPath $base) {
      foreach ($v in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
        foreach ($h in @("windows-x86_64", "linux-x86_64")) {
          $c = Join-Path $v.FullName ("toolchains\llvm\prebuilt\" + $h + "\bin\aarch64-linux-android28-clang.cmd")
          if (Test-Path -LiteralPath $c) { return @{ type = "win"; clang = $c } }
        }
      }
    }
  }
  # 2) WSL kali NDK (与历史构建同一工具链: /usr/lib/android-ndk)
  $wsl = wsl -d kali-linux -- bash -c "ls /usr/lib/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang 2>/dev/null || echo MISSING" 2>$null
  if ($wsl -and $wsl -notmatch "MISSING") {
    return @{ type = "wsl"; ndk_bin = "/usr/lib/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin" }
  }
  return $null
}

# ---------- NDK 自动下载 (v1.7, Windows 备选; WSL kali 已装时无需) ----------
function Ensure-NDK {
  $n = Find-NDK
  if ($n) {
    if ($n.type -eq "win") { SayOk "NDK clang: $($n.clang)" }
    else { SayOk "NDK (WSL kali): $($n.ndk_bin)" }
    return $n
  }
  if ($SkipDeps) { SayErr "未找到 NDK (离线模式 -SkipDeps). 手动: 设置 ANDROID_NDK_HOME, 或 WSL kali 安装 android-ndk"; return $null }
  SayWarn "未找到 NDK (exploit 编译需要 aarch64-linux-android28-clang)"
  $resp = Read-Host "是否自动下载 Android NDK r28 (Windows, ~1.1GB, Google 官方) 到项目根? (y/N)"
  if ($resp -notmatch '^[yY]') { SayErr "已取消; 可设置 ANDROID_NDK_HOME 或 WSL kali 装 NDK 后重试"; return $null }
  $dep = Get-DepsDir
  $zip = Join-Path $dep "android-ndk-r28-windows.zip"
  Say "下载 NDK r28 (约 1.1GB, 仅首次; 之后 deps 复用) ..."
  $ok = Download-Url "https://dl.google.com/android/repository/android-ndk-r28-windows.zip" $zip
  if (-not $ok) { SayErr "NDK 下载失败 (需联网). 手动: https://developer.android.com/ndk/downloads"; return $null }
  Say "解压 NDK ..."
  $ndkDir = Join-Path $dep "ndk"
  New-Item -ItemType Directory -Force -Path $ndkDir | Out-Null
  try { Expand-Archive -LiteralPath $zip -DestinationPath $ndkDir -Force }
  catch { SayErr "NDK 解压失败: $($_.Exception.Message)"; return $null }
  $n = Find-NDK
  if (-not $n) {
    $c = Get-ChildItem $ndkDir -Recurse -Filter "aarch64-linux-android28-clang.cmd" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { $n = @{ type = "win"; clang = $c.FullName } }
  }
  if ($n) { SayOk "NDK 已就绪: $($n.clang)"; return $n }
  SayErr "NDK 解压后未找到 clang"; return $null
}

# ---------- exploit 自动编译 (v1.7): 与历史构建同链 (WSL kali NDK + build 脚本) ----------
# 产物: devices/<id>/prebuilt/glt_esync + w2host (主链默认名)
function Invoke-ExploitBuild {
  param([string]$DeviceId)
  $ndk = Ensure-NDK
  if (-not $ndk) { return $null }
  $devDir = Join-Path $pkgRoot ("devices\" + $DeviceId)
  $prebuilt = Join-Path $devDir "prebuilt"
  New-Item -ItemType Directory -Force -Path $prebuilt | Out-Null
  $tmp = Join-Path $env:TEMP ("gl_build_" + $DeviceId + "_" + (Get-Date -Format "HHmmss"))
  New-Item -ItemType Directory -Force -Path $tmp | Out-Null
  $tmpWsl = ConvertTo-WslPath $tmp
  $gltOut = Join-Path $prebuilt "glt_esync"
  $ok = $true
  try {
    if ($ndk.type -eq "wsl") {
      # 与历史构建完全一致: WSL kali NDK + 仓库 build 脚本 (仅 glt 按机型编译;
      # w2host 采样窗口/候选范围运行时注入 W2_CRED_IPS 等, 无需重编, 复用仓库 prebuilt/w2host)
      $gltScript = ConvertTo-WslPath (Join-Path $pkgRoot "exploit\build\build_glt_esync.sh")
      $r = wsl -d kali-linux -- bash $gltScript -o $tmpWsl -t $DeviceId -n $ndk.ndk_bin 2>&1
      if ($LASTEXITCODE -ne 0) { SayErr "glt 编译失败: $($r | Select-Object -Last 3)"; $ok = $false }
      $gltRaw = Join-Path $tmp ("glt-" + $DeviceId + "-v1.0.elf")
      if ($ok -and (Test-Path -LiteralPath $gltRaw)) { Copy-Item -LiteralPath $gltRaw -Destination $gltOut -Force }
      elseif ($ok) { SayErr "glt 产物缺失"; $ok = $false }
    } else {
      # Windows NDK 直编 (与 build 脚本等价命令)
      $clang = $ndk.clang
      $src = Join-Path $pkgRoot "exploit\src"
      $vendored = Join-Path $pkgRoot "exploit\vendored"
      $assets = Join-Path $pkgRoot "exploit\assets"
      $bd = Join-Path $tmp ".gl_build"
      New-Item -ItemType Directory -Force -Path (Join-Path $bd "build\embed") | Out-Null
      New-Item -ItemType Directory -Force -Path (Join-Path $bd "assets") | Out-Null
      Copy-Item (Join-Path $assets "wallpaper.webp") (Join-Path $bd "assets\") -Force
      Push-Location $bd
      $r = & $clang -O2 -fPIE -pie -o (Join-Path $bd "build\embed\su_daemon_aarch64_pie") (Join-Path $src "su_daemon.c") 2>&1
      if ($LASTEXITCODE -ne 0) { SayErr "su_daemon 编译失败: $r"; $ok = $false }
      Pop-Location
      if ($ok) {
        Push-Location $bd
        $r = & $clang -O2 -static "-DTARGET_CONFIG_H=`"target.h`"" -I $src -I $vendored -I $devDir `
          -o $gltOut (Join-Path $src "main.c") (Join-Path $src "slide.c") (Join-Path $src "fops.c") `
          (Join-Path $src "util.c") (Join-Path $src "root.c") (Join-Path $src "pipe.c") `
          (Join-Path $src "preload.c") (Join-Path $src "su_blob.S") (Join-Path $src "wallpaper_blob.S") `
          (Join-Path $src "standalone_main.c") 2>&1
        if ($LASTEXITCODE -ne 0) { SayErr "glt 编译失败: $r"; $ok = $false }
        Pop-Location
      }
    }
  } finally {
    $tmpFull = [System.IO.Path]::GetFullPath($tmp)
    $tempFull = [System.IO.Path]::GetFullPath($env:TEMP)
    if ($tmpFull.StartsWith($tempFull)) { Remove-Item -LiteralPath $tmpFull -Recurse -Force -ErrorAction SilentlyContinue }
  }
  if (-not $ok) { return $null }
  if (Test-Path -LiteralPath $gltOut) {
    SayOk "exploit 自动编译完成: $gltOut (w2host 运行时自适应, 复用仓库 prebuilt/w2host)"
    return @{ glt = $gltOut }
  }
  SayErr "glt 产物缺失"; return $null
}

# ---------- 新机型偏移重建 (v1.6): 素材 -> package -> KMI 自动 -> prebuilt 门禁 ----------
# 设置脚本级: $GEN_WIN_OFFS / $ProfilePath / $ProfileInfo / $ModuleW2 / $ModuleGlt / $KO_ADAPTED / $PR_ADAPTED
# 返回: hashtable (ok) | "cancelled" | $null (失败)
function Invoke-DeviceBuild {
  param([string]$Asset, [string]$WorkDir)
  $oa = Join-Path $pkgRoot "tools\offset_tools\offsets_auto.py"
  $python = Find-Python
  if (-not $python) { SayErr "未找到 Python"; return $null }

  # 1. 素材预处理: zip/payload 先解出 boot.img/kernel.raw (package 需要 bootimg/raw/elf)
  $pkgAsset = $Asset
  $kind = Get-FileKind $Asset
  if ($kind -eq "fullzip" -or $kind -eq "payload") {
    Say "素材为 $kind, 先解出 boot.img ..."
    $payload = $Asset
    if ($kind -eq "fullzip") {
      $payload = Join-Path $WorkDir "payload.bin"
      Say "全量包 zip: 查找 payload.bin ..."
      try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $z = [System.IO.Compression.ZipFile]::OpenRead($Asset)
        $entry = $z.Entries | Where-Object { $_.FullName -match "payload\.bin$" } | Select-Object -First 1
        if ($entry) {
          [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $payload, $true)
          SayOk "payload.bin 已解出: $payload"
        }
        $z.Dispose()
      } catch { }
      if (-not (Test-Path -LiteralPath $payload)) { SayErr "zip 中未找到 payload.bin"; return $null }
    }
    $boot = Step-PayloadToBoot $payload $WorkDir
    if (-not $boot) { return $null }
    $pkgAsset = $boot
    $raw = Step-BootToRaw $boot $WorkDir
    if ($raw) { $pkgAsset = $raw }
  } elseif ($kind -eq "bootimg") {
    $raw = Step-BootToRaw $Asset $WorkDir
    if ($raw) { $pkgAsset = $raw }
  }
  SayOk "package 素材: $pkgAsset"

  # 2. package 主导 (offline+winoffs-image+pselect+header -> devices/<id>/)
  $newDevId = "auto_" + (Get-Date -Format "yyyyMMdd_HHmmss")
  $newDevDir = Join-Path $pkgRoot ("devices\" + $newDevId)
  $pkgLog = (& $python $oa package $pkgAsset --out $newDevDir --device-id $newDevId 2>&1 | Out-String)
  Log-Raw ("[package]`n" + $pkgLog)
  @($pkgLog -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 16) | ForEach-Object { Say $_ }
  $newWin = Join-Path $newDevDir "win_offs.json"
  if (-not (Test-Path -LiteralPath $newWin)) {
    SayErr "机型模块生成未产出 win_offs.json (素材解包/提取失败)"; return $null
  }
  $script:GEN_WIN_OFFS = $newWin
  $script:ProfilePath = Join-Path $newDevDir "device.json"
  try { $script:ProfileInfo = Get-Content -LiteralPath $script:ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
  SayOk "已生成机型模块: $newDevDir (分享: 打包该目录或拷贝到他人 devices/)"

  # 3. KMI 自动: 模块 kernel_release vs ko vermagic (-KernelRelease 手动覆盖)
  $script:KO_ADAPTED = $null
  $script:PR_ADAPTED = $null
  $krel = [string]$script:ProfileInfo.kernel_release
  if ($KernelRelease) { $krel = $KernelRelease }
  if ($krel) {
    $pv = Join-Path $pkgRoot "modules\kernelsu\patch_vermagic.py"
    $koSrc = Join-Path $pkgRoot "modules\kernelsu\kernelsu.ko"
    $koVm = Get-KoVermagic $koSrc
    if ($koVm -and $koVm -notlike ("*" + $krel + "*")) {
      SayWarn "kernelsu.ko vermagic 不匹配 ($krel), 自动重打 ..."
      $koOut = Join-Path $pkgRoot "prebuilt\kernelsu_adapted.ko"
      $koLog = (& $python $pv $koSrc $koOut --release $krel --no-sha-check 2>&1 | Out-String)
      Log-Raw ("[patch_vermagic kernelsu]`n" + $koLog)
      if (Test-Path -LiteralPath $koOut) {
        $script:KO_ADAPTED = $koOut
        SayOk "kernelsu.ko 已重打: $koOut"
        SayWarn "ko 仅改写 vermagic, 不保证 modversions ABI; patch_ko_all 会做符号重定位"
      } else { SayErr "kernelsu.ko 重打失败"; Show-Tail $koLog }
    } else { SayOk "kernelsu.ko vermagic 匹配模块内核" }
    $prSrc = Join-Path $pkgRoot "modules\permissive_restore\permissive_restore.ko"
    if (Test-Path -LiteralPath $prSrc) {
      $prVm = Get-KoVermagic $prSrc
      if ($prVm -and $prVm -notlike ("*" + $krel + "*")) {
        SayWarn "permissive_restore.ko vermagic 不匹配 ($krel), 自动重打 ..."
        $prOut = Join-Path $pkgRoot "prebuilt\permissive_restore_adapted.ko"
        $prLog = (& $python $pv $prSrc $prOut --release $krel --no-sha-check 2>&1 | Out-String)
        Log-Raw ("[patch_vermagic permissive_restore]`n" + $prLog)
        if (Test-Path -LiteralPath $prOut) { $script:PR_ADAPTED = $prOut; SayOk "permissive_restore.ko 已重打: $prOut" }
      }
    }
  }

  # 4. prebuilt 门禁 + 模块产物 (devices/<id>/prebuilt/)
  $script:ModuleW2 = $null
  $script:ModuleGlt = $null
  $modW2 = Join-Path $newDevDir "prebuilt\w2host"
  $modGlt = Join-Path $newDevDir "prebuilt\glt_esync"
  if ((Test-Path -LiteralPath $modW2) -and (Test-Path -LiteralPath $modGlt)) {
    $script:ModuleW2 = $modW2
    $script:ModuleGlt = $modGlt
    SayOk "模块自带 w2host/glt 产物, 主链将使用"
  } elseif (Test-Path -LiteralPath $modGlt) {
    # w2host 采样窗口/候选范围运行时注入 (W2_CRED_IPS 等), 无需按机型重编,
    # 主链回退仓库 prebuilt/w2host 即可
    $script:ModuleGlt = $modGlt
    SayOk "模块自带 glt_esync (按本机型编译), w2host 复用仓库 prebuilt (运行时自适应)"
  } elseif ($script:ProfileInfo.family -and [string]$script:ProfileInfo.family -ne "b57") {
    SayWarn "非 b57 机型且模块无自带 glt_esync 产物 (prebuilt/glt_esync 为 b57 编译, 偏移不匹配; w2host 运行时自适应可直接用)"
    $resp = Read-Host "是否自动编译本机型 exploit 产物? (WSL kali NDK / 自动下载 NDK; y/N)"
    if ($resp -match '^[yY]') {
      $built = Invoke-ExploitBuild -DeviceId $newDevId
      if ($built) {
        $script:ModuleGlt = $built.glt
        SayOk "主链将使用本机型自动编译产物"
      } else {
        SayErr "自动编译未完成; 手动: bash exploit/build/build_glt_esync.sh -t $newDevId -> devices\$newDevId\prebuilt\"
      }
    } else {
      SayWarn "跳过自动编译; 手动: bash exploit/build/build_glt_esync.sh -t $newDevId -> devices\$newDevId\prebuilt\"
    }
    if (-not $script:ModuleGlt) {
      $resp = Read-Host "是否仍用 b57 预编译产物强跑? (y/N)"
      if ($resp -notmatch '^[yY]') { SayErr "已取消 (主链未运行); 编译产物后再试"; return "cancelled" }
      SayWarn "继续使用 b57 预编译 glt_esync (偏移不匹配, 风险自担)"
    }
  }
  return @{ ok = $true; win_offs = $newWin; profile_path = $script:ProfilePath }
}

# Windows 路径 -> WSL 路径 (任意盘符, 旧实现只处理 D: 导致 C 盘 TEMP 时转换失败)
function ConvertTo-WslPath {
  param([string]$Path)
  $p = $Path -replace '\\','/'
  if ($p -match '^([A-Za-z]):(.*)$') { return ("/mnt/" + $matches[1].ToLower() + $matches[2]) }
  return $p
}

# ---------- 工具探测 ----------
function Find-Python {
  if ($Python) { return $Python }
  foreach ($c in @("python", "py", "python3")) {
    $p = (Get-Command $c -ErrorAction SilentlyContinue).Source
    if ($p) { return $p }
  }
  # 常见安装位置 (Scoop / Chocolatey / 官方 / WindowsApps)
  foreach ($cand in @(
      "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
      "$env:LOCALAPPDATA\Programs\Python\Launcher\py.exe",
      "C:\Python3*\python.exe",
      "$env:USERPROFILE\scoop\apps\python\current\python.exe",
      "C:\ProgramData\chocolatey\bin\python.exe")) {
    $hit = Get-Item $cand -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  # WindowsApps stub -> real python
  $wa = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
  if ($wa) {
    $real = & $wa -c "import sys; print(sys.executable)" 2>$null
    if ($real -match 'python') { return $real.Trim() }
  }
  return $null
}

function Find-PayloadTool {
  # 返回 @{type; cmd} 或 $null
  # 1) payload-dumper-go (任意平台, 独立二进制)
  $g = (Get-Command payload-dumper-go -ErrorAction SilentlyContinue).Source
  if ($g) { return @{ type="go"; cmd=$g } }
  # 2) payload_dumper.py (user-provided, placed inside the package)
  foreach ($cand in @(
      (Join-Path $pkgRoot "payload_dumper.py"),
      (Join-Path $pkgRoot "tools\payload_dumper.py"))) {
    if (Test-Path $cand) { return @{ type="py"; cmd=$cand } }
  }
  # 3) 已下载的 payload-dumper-go (DepsDir: 项目根目录 或 %LOCALAPPDATA% 旧位置)
  foreach ($dep in @((Get-DepsDir), (Join-Path $env:LOCALAPPDATA "GhostLock-X200\deps"))) {
    foreach ($cand in @(
        (Join-Path $dep "payload-dumper-go\payload-dumper-go.exe"),
        (Join-Path $dep "payload-dumper-go\payload-dumper-go"))) {
      if (Test-Path $cand) { return @{ type="go"; cmd=$cand } }
    }
  }
  return $null
}

function Find-VmlinuxToElf {
  # 返回 @{type; cmd} 或 $null
  $w = (Get-Command vmlinux-to-elf -ErrorAction SilentlyContinue).Source
  if ($w) { return @{ type="bin"; cmd=$w } }
  $py = Find-Python
  if ($py) {
    $r = & $py -c "import vmlinux_to_elf; print('ok')" 2>$null
    if ($r -match "ok") { return @{ type="pymod"; cmd=$py } }
  }
  $wsl = & wsl -d kali-linux -- bash -lc "which vmlinux-to-elf 2>/dev/null" 2>$null
  if ($wsl) { return @{ type="wslbin"; cmd="vmlinux-to-elf" } }
  return $null
}

function Find-Adb {
  return (Get-AdbPath -Preferred $AdbPath -PackageRoot $pkgRoot -ExtraCandidates @(
    (Join-Path $env:LOCALAPPDATA "GhostLock-X200\deps\platform-tools\adb.exe"),
    (Join-Path (Get-DepsDir) "platform-tools\adb.exe")))
}

# ---------- 依赖自动下载 (开箱即用; -SkipDeps 关闭) ----------
function Get-DepsDir {
  # 优先级: -DepsDir 显式指定 > 默认项目根目录 (包内自包含); 项目根不可写时回退 %LOCALAPPDATA% 旧位置
  if ($DepsDir) { $d = $DepsDir }
  else { $d = $pkgRoot }
  try {
    New-Item -ItemType Directory -Force -Path $d -ErrorAction Stop | Out-Null
    $probe = Join-Path $d ("__w_" + [guid]::NewGuid().ToString('N'))
    Set-Content -LiteralPath $probe -Value 'x' -ErrorAction Stop
    Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
  } catch {
    $d = Join-Path $env:LOCALAPPDATA "GhostLock-X200\deps"
    New-Item -ItemType Directory -Force -Path $d -ErrorAction SilentlyContinue | Out-Null
  }
  return [System.IO.Path]::GetFullPath($d)
}

function Test-PyDeps {
  param([string]$Py)
  if (-not $Py) { return $false }
  $r = & $Py -c "import capstone, elftools; print('ok')" 2>$null
  return ($r -match 'ok')
}

function Download-Url {
  # curl.exe (Win10+ 自带) 优先; 失败回退 Invoke-WebRequest
  param([string]$Url, [string]$OutFile)
  $curl = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
  if ($curl) {
    & $curl.exe --noproxy "*" -L --retry 3 --retry-delay 2 -sS -o $OutFile $Url 2>$null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $OutFile) -and (Get-Item $OutFile).Length -gt 0) { return $true }
  }
  try {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
    if ((Get-Item $OutFile).Length -gt 0) { return $true }
  } catch { }
  return $false
}

function Ensure-Adb {
  # 找不到 adb 时自动下载官方 platform-tools 并设置 ANDROID_ADB
  $a = Find-Adb
  if ($a) { return $a }
  if ($SkipDeps) {
    SayErr "未找到 adb. 请安装 platform-tools 或设置 ANDROID_ADB (或去掉 -SkipDeps 自动下载)"; return $null
  }
  SayWarn "未找到 adb, 正在自动下载官方 platform-tools (约 8MB) ..."
  $dep = Get-DepsDir
  $zip = Join-Path $dep "platform-tools-latest-windows.zip"
  $ok = Download-Url "https://dl.google.com/android/repository/platform-tools-latest-windows.zip" $zip
  if (-not $ok) { SayErr "platform-tools 下载失败 (需联网). 请手动安装: https://developer.android.com/tools/releases/platform-tools"; return $null }
  try {
    Expand-Archive -Path $zip -DestinationPath $dep -Force
  } catch {
    # 手动解压
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $dep, $true)
  }
  $adbExe = Join-Path $dep "platform-tools\adb.exe"
  if (Test-Path $adbExe) {
    if (Test-AdbWorking $adbExe) {
      $env:ANDROID_ADB = $adbExe
      SayOk "adb 已自动安装: $adbExe"
      return $adbExe
    }
    SayErr "下载的 adb.exe 校验失败 (残缺文件?), 请手动安装 platform-tools 或重试"; return $null
  }
  SayErr "platform-tools 解压后未找到 adb.exe: $dep"; return $null
}

function Ensure-PythonDeps {
  # 确保 python 存在且 capstone/pyelftools 可用
  $py = Find-Python
  if (-not $py) {
    if ($SkipDeps) { SayErr "未找到 Python (已禁用自动安装)"; return $null }
    SayWarn "未找到 Python, 尝试自动安装 (winget) ..."
    $winget = (Get-Command winget -ErrorAction SilentlyContinue).Source
    if ($winget) {
      & $winget install --id Python.Python.3 --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
      $py = Find-Python
    }
    if (-not $py) {
      SayErr "Python 自动安装失败. 请手动安装: https://www.python.org/downloads/ (勾选 Add to PATH)"
      return $null
    }
    SayOk "Python 已安装: $py"
  }
  if (Test-PyDeps $py) { return $py }
  if ($SkipDeps) { SayErr "缺少 Python 依赖 (capstone/pyelftools). 运行: $py -m pip install -r tools\offset_tools\requirements.txt"; return $null }
  SayWarn "安装 Python 依赖 (capstone, pyelftools) ..."
  & $py -m pip install -r (Join-Path $pkgRoot "tools\offset_tools\requirements.txt") 2>&1 | Out-Null
  if (Test-PyDeps $py) { SayOk "Python 依赖已安装"; return $py }
  SayErr "pip 安装失败 (需联网). 手动: $py -m pip install -r tools\offset_tools\requirements.txt"; return $null
}

function Ensure-PayloadTool {
  # 需要 payload 解包时调用; 找不到则自动下载 payload-dumper-go (GitHub release)
  $t = Find-PayloadTool
  if ($t) { return $t }
  if ($SkipDeps) {
    SayErr "未找到 payload 提取工具 (离线模式). 请手动安装 payload-dumper-go: https://github.com/ssut/payload-dumper-go"
    return $null
  }
  SayWarn "未找到 payload 提取工具, 自动下载 payload-dumper-go (Apache-2.0, GitHub release) ..."
  $dep = Get-DepsDir
  $tgz = Join-Path $dep "payload-dumper-go_windows_amd64.tar.gz"
  $ok = Download-Url "https://github.com/ssut/payload-dumper-go/releases/download/1.3.0/payload-dumper-go_1.3.0_windows_amd64.tar.gz" $tgz
  if (-not $ok) { SayErr "payload-dumper-go 下载失败 (需联网). 手动: https://github.com/ssut/payload-dumper-go/releases"; return $null }
  $exeDir = Join-Path $dep "payload-dumper-go"
  New-Item -ItemType Directory -Force -Path $exeDir | Out-Null
  try {
    & tar.exe -xzf $tgz -C $exeDir 2>$null
    if ($LASTEXITCODE -ne 0) { throw "tar failed" }
  } catch {
    try {
      # fallback: tar via .NET? 用系统 tar 已覆盖; 否则报错
      throw "untar failed: $_"
    } catch { }
  }
  $go = Get-ChildItem $exeDir -Recurse -Filter "payload-dumper-go.exe" | Select-Object -First 1
  if ($go) {
    SayOk "payload-dumper-go 已自动安装: $($go.FullName)"
    return @{ type="go"; cmd=$go.FullName }
  }
  # 也接受 tar 解出的是 payload-dumper-go (无 .exe 后缀的 ELF/PE)
  $go2 = Get-ChildItem $exeDir -Recurse -Filter "payload-dumper-go" | Select-Object -First 1
  if ($go2) { return @{ type="go"; cmd=$go2.FullName } }
  SayErr "payload-dumper-go 解压失败: $exeDir"; return $null
}

function Ensure-VmlinuxToElf {
  # 需要 kernel Image -> ELF 时调用; 优先本机已有, 其次 pip, 最后 WSL
  $t = Find-VmlinuxToElf
  if ($t) { return $t }
  if ($SkipDeps) {
    SayErr "未找到 vmlinux-to-elf (离线模式). 手动: pip install vmlinux-to-elf (或 WSL 安装)"
    return $null
  }
  $py = Find-Python
  if ($py) {
    SayWarn "未找到 vmlinux-to-elf, 尝试 pip 安装 (GPL-3.0) ..."
    & $py -m pip install vmlinux-to-elf 2>&1 | Out-Null
    $t = Find-VmlinuxToElf
    if ($t) { SayOk "vmlinux-to-elf 已安装 (pip)"; return $t }
  }
  # pip 失败 (Windows 常因 minilzo 需 MSVC 编译) -> 回退 WSL
  $t = Find-VmlinuxToElf   # 再查一次 (可能 pip 部分成功 / WSL 可探测)
  if ($t) { return $t }
  $wslAvail = (Get-Command wsl -ErrorAction SilentlyContinue).Source
  if ($wslAvail) {
    SayWarn "pip 安装不可用 (Windows 需 MSVC Build Tools 编译 minilzo), 尝试 WSL 安装 ..."
    & wsl -d kali-linux -- bash -lc "command -v vmlinux-to-elf >/dev/null 2>&1 || pip3 install vmlinux-to-elf 2>&1 | tail -2" 2>&1 | Out-Null
    $t = Find-VmlinuxToElf
    if ($t) { SayOk "vmlinux-to-elf 已安装 (WSL)"; return $t }
  }
  SayErr "vmlinux-to-elf 安装失败. 请任选其一:"
  SayErr "  Windows: 安装 MSVC C++ Build Tools 后重跑, 或 pip install vmlinux-to-elf"
  SayErr "  WSL:     wsl -d kali-linux -- bash -lc 'pip3 install vmlinux-to-elf'"
  SayErr "  或:      直接提供现成 kernel.elf 作为素材 (脚本自动识别并跳过此工具)"
  return $null
}


# ---------- 步骤: 提取 payload -> boot.img ----------
function Step-PayloadToBoot {
  param([string]$PayloadPath, [string]$OutDir)
  $tool = Ensure-PayloadTool
  if (-not $tool) {
    SayErr "或者直接提供已解出的 boot.img / kernel.elf, 重新运行本脚本 (-AssetPath)"
    return $null
  }
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  Say "用 payload 工具提取 boot.img ..."
  if ($tool.type -eq "go") {
    Push-Location $OutDir
    $output = (& $tool.cmd $PayloadPath 2>&1 | Out-String)
    Pop-Location
  } elseif ($tool.type -eq "py") {
    $py = Find-Python
    $output = (& $py $tool.cmd $PayloadPath --out $OutDir --images boot 2>&1 | Out-String)
  }
  Log-Raw ("[payload 提取]`n" + $output)
  $boot = Join-Path $OutDir "boot.img"
  if (-not (Test-Path $boot)) {
    # 有些工具输出到 out/ 或直接当前目录
    $boot = (Get-ChildItem $OutDir -Recurse -Filter "boot.img" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
  }
  if (-not $boot) { SayErr "payload 提取未产生 boot.img, 请手动解包后重跑"; Show-Tail $output; return $null }
  SayOk "boot.img 已提取: $boot"
  return $boot
}

# ---------- 步骤: boot.img -> kernel.raw (unpack_boot.py, 自带) ----------
function Step-BootToRaw {
  param([string]$BootImg, [string]$OutDir)
  $unpack = Join-Path $pkgRoot "tools\offset_tools\unpack_boot.py"
  $py = Find-Python
  if (-not $py) { SayErr "未找到 Python"; return $null }
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  Push-Location $OutDir
  $output = (& $py $unpack $BootImg $OutDir 2>&1 | Out-String)
  Pop-Location
  Log-Raw ("[unpack_boot.py]`n" + $output)
  $raw = Join-Path $OutDir "kernel.raw"
  if (-not (Test-Path $raw)) { $raw = Join-Path $OutDir "Image" }
  if (-not (Test-Path $raw)) { SayErr "unpack_boot.py 未产出 kernel.raw/Image"; Show-Tail $output; return $null }
  $rawSize = (Get-Item $raw).Length
  if ($rawSize -lt 1MB) {
    SayErr ("kernel.raw 过小 (" + $rawSize + " 字节), 此镜像不含内核, 疑似选成了 init_boot.img / vendor_boot.img")
    SayErr "请改选 boot.img (payload 里的 boot 分区), 或直接选全量包 zip / payload.bin 让脚本自动解包"
    SayErr "若确认该文件是压缩内核, 可把 kernel.raw 直接作为素材 (-AssetPath) 重试"
    return $null
  }
  SayOk ("kernel 镜像已解出: " + $raw + " (" + $rawSize + " 字节)")
  return $raw
}

# ---------- 步骤: kernel.raw -> kernel.elf (vmlinux-to-elf, 外部依赖) ----------
function Step-RawToElf {
  param([string]$Raw, [string]$OutDir)
  $tool = Ensure-VmlinuxToElf
  if (-not $tool) {
    SayErr "无法转换 kernel Image -> ELF (vmlinux-to-elf 不可用), 请检查网络/依赖"
    return $null
  }
  $out = Join-Path $OutDir "kernel.elf"
  $output = ""
  if ($tool.type -eq "bin") {
    $output = (& $tool.cmd $Raw $out 2>&1 | Out-String)
  } elseif ($tool.type -eq "pymod") {
    $output = (& $tool.cmd -m vmlinux_to_elf $Raw $out 2>&1 | Out-String)
  } elseif ($tool.type -eq "wslbin") {
    $wRaw = ConvertTo-WslPath $Raw
    $wOut = ConvertTo-WslPath $out
    $output = (& wsl -d kali-linux -- bash -lc "vmlinux-to-elf '$wRaw' '$wOut'" 2>&1 | Out-String)
  }
  Log-Raw ("[vmlinux-to-elf]`n" + $output)
  if (-not (Test-Path $out)) {
    SayErr "vmlinux-to-elf 转换失败 (无输出 kernel.elf)"
    SayErr "--- vmlinux-to-elf 原始输出 (最后 20 行) ---"
    Show-Tail $output
    SayErr "--- 结束 ---"
    return $null
  }
  SayOk "kernel ELF 已生成: $out"
  return $out
}

# ---------- 步骤: kernel.elf -> win_offs.json (offsets_auto.py winoffs, 自带) ----------
function Step-ElfToWinOffs {
  param([string]$Elf, [string]$OutDir)
  $oa = Join-Path $pkgRoot "tools\offset_tools\offsets_auto.py"
  $py = Find-Python
  if (-not $py) { SayErr "未找到 Python"; return $null }
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  $out = Join-Path $OutDir ("win_offs_" + (Split-Path $Elf -Leaf).Replace('.','_') + ".json")
  Push-Location $OutDir
  $output = (& $py $oa winoffs $Elf $out --profile $ProfilePath 2>&1 | Out-String)
  Pop-Location
  Log-Raw ("[winoffs]`n" + $output)
  @($output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 3) | ForEach-Object { Say "winoffs: $_" }
  if (-not (Test-Path $out)) { SayErr "offsets_auto.py winoffs 失败 (无输出)"; Show-Tail $output; return $null }
  SayOk "win_offs 已生成: $out"
  return $out
}

# ---------- kernel.elf 提供引导 (vmlinux-to-elf 不可用时, 主动让用户提供现成文件) ----------
function Offer-KernelElf {
  SayErr "本机无法自动转换 kernel.elf (Windows pip 依赖 minilzo, 需 MSVC 编译; 或需 WSL kali-linux)。"
  Say "获取 kernel.elf 的三种方式 (任选其一):"
  Say "  A) 在任一装有 WSL(推荐 kali-linux) 的电脑上执行两条命令:"
  Say "     wsl -d kali-linux -- bash -lc 'pip3 install vmlinux-to-elf'"
  Say "     wsl -d kali-linux -- bash -lc \"vmlinux-to-elf '/mnt/c/你的路径/kernel.raw' '/mnt/c/你的路径/kernel.elf'\""
  Say "     (kernel.raw 可由本工具从 boot.img 解出, 脚本会提示路径)"
  Say "  B) 安装 Windows MSVC C++ Build Tools 后重跑本工具 (自动 pip 安装 vmlinux-to-elf)"
  Say "  C) 联系维护者: 提供 boot.img / 全量包 zip, 由维护者代转 kernel.elf 后返回;"
  Say "     或向同机型/同固件的他人索取现成 kernel.elf (本工具支持直接以 kernel.elf 为素材)"
  $resp = Read-Host "若你已有现成 kernel.elf, 输入 y 选择文件继续; 直接回车则退出"
  if ($resp -match '^[yY]') {
    $f = Pick-File "请选择 kernel.elf" "ELF 文件 (*.elf)|*.elf|All files (*.*)|*.*"
    if ($f -and (Test-Path -LiteralPath $f)) {
      try {
        $fs = [System.IO.File]::OpenRead($f)
        $b = New-Object byte[] 4
        $fs.Read($b, 0, 4) | Out-Null
        $fs.Close()
        if ($b[0] -eq 0x7f -and $b[1] -eq 0x45 -and $b[2] -eq 0x4c -and $b[3] -eq 0x46) {
          SayOk "kernel.elf 已确认: $f"
          return $f
        }
        SayErr "所选文件不是 ELF 格式, 已取消"; return $null
      } catch { SayErr "读取文件失败: $_"; return $null }
    }
    SayErr "未选择有效文件"; return $null
  }
  return $null
}

# ---------- 一键: 素材 -> win_offs ----------
function Build-WinOffsFromAsset {
  param([string]$Asset, [string]$WorkDir)
  $kind = Get-FileKind $Asset
  Say "识别素材类型: $kind ($Asset)"
  $elf = $null
  switch ($kind) {
    "kernel_elf" { $elf = $Asset }
    "kernel_raw" { $elf = Step-RawToElf $Asset $WorkDir }
    "bootimg" {
      $raw = Step-BootToRaw $Asset $WorkDir
      if (-not $raw) { return $null }
      $elf = Step-RawToElf $raw $WorkDir
    }
    "payload" {
      $boot = Step-PayloadToBoot $Asset $WorkDir
      if (-not $boot) { return $null }
      $raw = Step-BootToRaw $boot $WorkDir
      if (-not $raw) { return $null }
      $elf = Step-RawToElf $raw $WorkDir
    }
    "fullzip" {
      # 全量包 zip: 先解出 payload.bin
      Say "全量包 zip: 查找 payload.bin ..."
      $zip = $Asset
      $payload = Join-Path $WorkDir "payload.bin"
      try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $z = [System.IO.Compression.ZipFile]::OpenRead($zip)
        $entry = $z.Entries | Where-Object { $_.FullName -match "payload\.bin$" } | Select-Object -First 1
        if ($entry) {
          [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $payload, $true)
          SayOk "payload.bin 已从 zip 解出: $payload"
        }
        $z.Dispose()
      } catch { }
      if (-not (Test-Path $payload)) { SayErr "zip 中未找到 payload.bin"; return $null }
      $boot = Step-PayloadToBoot $payload $WorkDir
      if (-not $boot) { return $null }
      $raw = Step-BootToRaw $boot $WorkDir
      if (-not $raw) { return $null }
      $elf = Step-RawToElf $raw $WorkDir
    }
    default { SayErr "无法识别的文件类型: $Asset"; return $null }
  }
  if (-not $elf) { $elf = Offer-KernelElf }
  if (-not $elf) { SayErr "未能得到 kernel ELF, 无法生成偏移"; return $null }
  $wo = Step-ElfToWinOffs $elf $WorkDir
  return $wo
}

# ============================================================
# 异常重启诊断: 自动采集 -> manifest -> zip -> 指引
# 输出内容面向 AI/维护者: UTF-8 纯文本, 每个文件带文件头注释,
# 附带 00_manifest.json (机器可读索引) 与 99_READ_ME.txt (阅读指南).
# 只采集低噪音高价值项, 不抓全量 logcat/getprop/系统日志目录.
# 安全约束 (保证采集本身不会引发 panic):
#   - 全部为只读 adb 命令, 不写设备关键区 (仅读 /data/local/tmp 等普通文件);
#   - 流式节点 (/dev/kmsg /proc/kmsg) 一律不使用, 内核日志走 dmesg 快照;
#   - 采集只在主链进程退出后执行, 不与任何写操作并发;
#   - 设备掉线时命令立即失败返回空, 不等待、不重试、不阻塞.
# ============================================================
function AdbSh([string]$Cmd) {
  if (-not $adb -or -not $serial) { return "" }
  try { return ((& $adb -s $serial shell $Cmd 2>$null | Out-String) -replace "`r?`n$", "").Trim() } catch { return "" }
}

function Get-DeviceOnline {
  $m = @(& $adb devices 2>$null | Select-String "`tdevice$")
  return ($m.Count -gt 0)
}

function Wait-DeviceOnline {
  param([int]$Minutes = 12)
  for ($i = 0; $i -lt ($Minutes * 60 / 10); $i++) {
    if (Get-DeviceOnline) { return $true }
    Start-Sleep -Seconds 10
  }
  return $false
}

function Get-BootIdNow { return (AdbSh "cat /proc/sys/kernel/random/boot_id 2>/dev/null") }

function Get-BootReasonNow {
  $a = AdbSh "getprop ro.boot.bootreason"
  $b = AdbSh "getprop sys.boot.reason"
  $s = ($a + " | " + $b).Trim()
  return $s.Trim(" |")
}

function Get-BuildHash([string]$Ver) {
  if ($Ver -match 'g([0-9a-f]{12})') { return $matches[1] }
  return ""
}

# 统一文件头: 每个采集文件首 4 行说明用途, 便于 AI 解析
function Write-DiagFile {
  param([string]$Path, [string]$Title, [string]$Content, [string]$Note = "")
  $header = @(
    "# ============================================================",
    "# file:   " + (Split-Path $Path -Leaf),
    "# 内容:   " + $Title,
    "# 采集时间: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  )
  if ($Note) { $header += ("# 备注:   " + $Note) }
  $header += ("# ============================================================")
  if ([string]::IsNullOrEmpty($Content)) { $Content = "(空 / 无内容)" }
  (@($header) + @($Content)) | Out-File -FilePath $Path -Encoding utf8
}

function New-DiagEntry {
  param([string]$OutDir, [string]$Name, [string]$Note)
  $p = Join-Path $OutDir $Name
  $sz = 0
  if (Test-Path -LiteralPath $p -PathType Container) {
    $sz = (Get-ChildItem -LiteralPath $p -Recurse -File | Measure-Object -Property Length -Sum).Sum
  } elseif (Test-Path -LiteralPath $p) {
    $sz = (Get-Item -LiteralPath $p).Length
  }
  if ($null -eq $sz) { $sz = 0 }   # 空目录时 Measure-Object Sum 为 $null, 归一为 0
  return @{ name = $Name; size = $sz; note = $Note }
}

# ---------- 诊断日志降体积: 关键行提取 + 尾部保留 + 连续重复压缩 ----------
# 目的: dmesg/pstore 动辄 2-4MB, 大部分是 vendor 刷屏; 关键信息 (panic 栈/错误/
#       阶段) 集中在尾部与强模式行附近, 摘要后体积可降 10 倍以上且不丢关键证据.
function Compress-ConsecutiveDup {
  param([string[]]$Lines)
  $sb = [System.Text.StringBuilder]::new()
  $prev = $null
  $count = 0
  foreach ($ln in $Lines) {
    if ($ln -eq $prev) { $count++ }
    else {
      if ($null -ne $prev) {
        if ($count -gt 1) { $null = $sb.AppendLine(("(x{0}) {1}" -f $count, $prev)) }
        else { $null = $sb.AppendLine($prev) }
      }
      $prev = $ln
      $count = 1
    }
  }
  if ($null -ne $prev) {
    if ($count -gt 1) { $null = $sb.AppendLine(("(x{0}) {1}" -f $count, $prev)) }
    else { $null = $sb.AppendLine($prev) }
  }
  return $sb.ToString()
}

function Reduce-DiagText {
  param([string]$Content, [int]$TailLines = 1500, [int]$Context = 2)
  if ([string]::IsNullOrEmpty($Content)) { return @{ tail = ''; key = ''; origLines = 0; keyLines = 0 } }
  $lines = @($Content -split "`n" | ForEach-Object { $_.TrimEnd("`r") })
  $origLines = $lines.Count
  # 只匹配真正的内核异常/崩溃模式; \b 词边界防误匹配 (如 debug: 里的 bug:); 不含裸 watchdog
  $strong = '\bKernel panic\b|\bnot syncing\b|\bBUG\b|\bCall trace\b|\bCall Trace\b|\bUnable to handle\b|\bSError\b|synchronous abort|\bOops\b|\boops\b|\bsoft lockup\b|\bhard lockup\b|rcu.*stall|\buse-after-free\b|\bdouble free\b|\brefcount\b|\bOut of memory\b|\bKilled process\b|\bFATAL\b|\bgeneral protection fault\b|\bNULL pointer dereference\b'
  $keyIdx = @{}
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match $strong) {
      for ($j = [Math]::Max(0, $i - $Context); $j -le [Math]::Min($lines.Count - 1, $i + $Context); $j++) {
        if (-not $keyIdx.ContainsKey($j)) { $keyIdx[$j] = $true }
      }
    }
  }
  $keyLines = 0
  $sb = [System.Text.StringBuilder]::new()
  foreach ($idx in ($keyIdx.Keys | Sort-Object)) {
    $keyLines++
    $null = $sb.AppendLine(("L{0}: {1}" -f ($idx + 1), $lines[$idx]))
  }
  $tailStart = [Math]::Max(0, $lines.Count - $TailLines)
  $tail = Compress-ConsecutiveDup $lines[$tailStart..($lines.Count - 1)]
  return @{ tail = $tail; key = $sb.ToString(); origLines = $origLines; keyLines = $keyLines }
}

# ---------- AI 速读摘要: 从各采集文件提炼为单文件 00_SUMMARY.txt ----------
function Build-DiagSummary {
  param($Manifest, [string]$DiagDir, [string]$MainOutput)
  $L = [System.Collections.Generic.List[string]]::new()
  $L.Add('# GhostLock-X200 诊断摘要')
  $L.Add('')
  $L.Add('## 1. 设备与内核')
  $L.Add(('brand=' + $Manifest.device.brand + ' model=' + $Manifest.device.model + ' build=' + $Manifest.device.build + ' sdk=' + $Manifest.device.sdk))
  $L.Add(('kernel=' + $Manifest.device.kernel_version))
  $match = [bool]($Manifest.device.kernel_build_hash -and $Manifest.device.kernel_build_hash -eq $Manifest.device.expected_kernel_build)
  $L.Add(('kernel_build_hash=' + $Manifest.device.kernel_build_hash + ' expected=' + $Manifest.device.expected_kernel_build + ' match=' + $match))
  $L.Add(('boot_id=' + $Manifest.boot.boot_id))
  $L.Add(('bootreason=' + $Manifest.boot.reason_raw + '  =>  ' + $Manifest.boot.panic_likely))
  $L.Add('')
  $L.Add('## 2. 运行结果')
  $L.Add(('mode=' + $Manifest.mode + ' collect_time=' + $Manifest.collect_time))
  $tailLines = @($MainOutput -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 6)
  if ($tailLines) { $L.AddRange([string[]]$tailLines) }
  $seq = Get-ChildItem -LiteralPath (Join-Path $DiagDir '06_local_tmp') -Filter 'glt_seq_*.txt' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
  if ($seq) {
    $L.Add('')
    $L.Add('## 3. 最后动作 (glt_seq 最后 6 行)')
    $seqLines = @(Get-Content -LiteralPath $seq.FullName | Where-Object { $_.Trim() -and $_.Trim() -notmatch '^#' } | Select-Object -Last 6)
    if ($seqLines) { $L.AddRange([string[]]$seqLines) }
  }
  $psFiles = Get-ChildItem -LiteralPath (Join-Path $DiagDir '02_pstore') -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'ramoops' }
  if ($psFiles) {
    $L.Add('')
    $L.Add('## 4. panic 证据 (pstore 关键行, 每文件前 20 条)')
    $panicPat = '\bKernel panic\b|\bnot syncing\b|\bBUG\b|\bCall trace\b|\bCall Trace\b|\bUnable to handle\b|\bSError\b|synchronous abort|\bOops\b|\boops\b|\bsoft lockup\b|\bhard lockup\b|rcu.*stall|\buse-after-free\b|\bdouble free\b|\brefcount\b|\bOut of memory\b|\bKilled process\b|\bFATAL\b|\bgeneral protection fault\b|\bNULL pointer dereference\b'
    foreach ($pf in $psFiles) {
      $c = Get-Content -LiteralPath $pf.FullName -Raw
      $keyStart = $c.IndexOf('关键行')
      if ($keyStart -ge 0) {
        $keyLines = @($c.Substring($keyStart) -split "`r?`n" | Where-Object { $_ -match '^L[0-9]+: ' -and $_ -match $panicPat } | Select-Object -First 20)
        if ($keyLines.Count -gt 0) {
          $L.Add(('--- ' + $pf.Name + ' ---'))
          $L.AddRange([string[]]$keyLines)
        }
      }
    }
  }
  $mod = Get-ChildItem -LiteralPath (Join-Path $DiagDir '06_local_tmp') -Filter 'diag_root_*modules*' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($mod) {
    $L.Add('')
    $L.Add('## 5. 模块状态 (diag_root modules)')
    $mc = @(Get-Content -LiteralPath $mod.FullName | Where-Object { $_ -match 'kernelsu|permissive_restore' })
    if ($mc) { $L.AddRange([string[]]$mc) }
  }
  $L.Add('')
  $L.Add('## 6. 结论建议')
  $hash = $Manifest.device.kernel_build_hash
  if ($hash -and $hash -ne $Manifest.device.expected_kernel_build) {
    $L.Add('- 内核构建不匹配预期: 极可能机型/系统版本不兼容; 需按目标内核重新编译/适配模块 (二次开发).')
  } else {
    $L.Add('- 内核构建与预期一致: 失败属运行期问题, 以第 2/3 节定位失败阶段与最后动作.')
  }
  if ($Manifest.boot.reason_raw -match 'panic|watchdog|wdt') { $L.Add('- 启动原因为 panic/watchdog: 结合第 4 节 pstore 确认崩溃点.') }
  if ($mod) { $L.Add('- 已到达 STAGE6 root 阶段 (存在 root 级快照): 偏移/提权链路工作正常, 问题在后半段 (INSMOD/验证).') }
  $L.Add('- 完整细节见各分项文件 (00_manifest.json 索引); 如需完整 dmesg 可另行抓取.')
  return ($L -join "`n")
}

function Collect-PanicDiag {
  param([string]$OutDir, [string]$Mode = "failure")   # Mode: panic=异常重启后采集 / failure=未重启现场采集
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $files = @()
  # 预期内核构建 hash (v1.4: 从命中机型模块读取, 不再硬编码)
  $expectedKernel = ""
  if ($ProfileInfo.kernel_release -and $ProfileInfo.kernel_release -match "g([0-9a-f]{6,})") {
    $expectedKernel = $matches[1]
  }

  # ---- 01_boot_info.txt: 白名单属性 (不抓全量 getprop, 避免噪音) ----
  $lines = @()
  foreach ($p in @("ro.boot.bootreason", "sys.boot.reason", "ro.boot.hardware",
      "ro.product.brand", "ro.product.model", "ro.build.version.release",
      "ro.build.version.sdk", "ro.build.display.id")) {
    $lines += ($p + "=" + (AdbSh ("getprop " + $p)))
  }
  $kv = AdbSh "cat /proc/version 2>/dev/null | head -1"
  $lines += ("kernel.version=" + $kv)
  $lines += ("kernel.build_hash=" + (Get-BuildHash $kv))
  $lines += ("uptime.sec=" + (AdbSh "cat /proc/uptime 2>/dev/null"))
  $lines += ("boot_id=" + (Get-BootIdNow))
  $lines += ("lsmod=" + (AdbSh "cat /proc/modules 2>/dev/null | head -20"))
  $f = Join-Path $OutDir "01_boot_info.txt"
  Write-DiagFile $f "机型/内核/启动原因等关键属性 (白名单)" ($lines -join "`n")
  $files += New-DiagEntry $OutDir "01_boot_info.txt" "机型/内核/启动原因关键属性, 分析起点"

  # ---- 02_pstore: panic 瞬间内核日志 (ramoops, 最高价值) ----
  $psDir = Join-Path $OutDir "02_pstore"
  New-Item -ItemType Directory -Force -Path $psDir | Out-Null
  (AdbSh "ls -la /sys/fs/pstore/ 2>&1") | Out-File (Join-Path $psDir "listing.txt") -Encoding utf8
  $psNames = @((AdbSh "ls /sys/fs/pstore/ 2>/dev/null") -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  foreach ($n in $psNames) {
    if ($n -match '^pmsg-') { continue }   # pmsg 为二进制且可能含用户数据, 不采集
    $safe = ($n -replace '[^\w\.\-]', '_')
    $content = AdbSh ("cat /sys/fs/pstore/" + $n + " 2>&1")
    $r = Reduce-DiagText $content 2000 2
    $body = "===== 关键行 (带上下文, " + $r.keyLines + " 行 / 原文 " + $r.origLines + " 行) =====`n" + $r.key + "`n`n===== 尾部 " + [Math]::Min(2000, $r.origLines) + " 行 (连续重复已压缩) =====`n" + $r.tail
    Write-DiagFile (Join-Path $psDir $safe) ("pstore: " + $n + " (摘要)") $body ("panic 栈通常在尾部/关键行; 原文 " + $r.origLines + " 行")
  }
  $files += New-DiagEntry $OutDir "02_pstore" "panic 瞬间内核日志 (摘要: 尾部+关键行); listing.txt 记录可读性"

  # ---- 03_last_kmsg / 04_dmesg: 重启后尽力而为 (受限时注明原因, 不留空噪音) ----
  $lk = AdbSh "cat /proc/last_kmsg 2>&1"
  $f = Join-Path $OutDir "03_last_kmsg.txt"
  Write-DiagFile $f "last_kmsg (旧内核遗留, 现代内核通常为空)" $lk "存在则为 panic 前内核日志"
  $files += New-DiagEntry $OutDir "03_last_kmsg.txt" "last_kmsg 尝试"
  $dm = AdbSh "dmesg 2>&1"
  $f = Join-Path $OutDir "04_dmesg.txt"
  if ([string]::IsNullOrEmpty($dm)) {
    Write-DiagFile $f "重启后 dmesg 尝试" "" "dmesg 受限 (dmesg_restrict=1, 重启后无 root), 内核日志请以 02_pstore 为准"
  } else {
    $r = Reduce-DiagText $dm 1500 2
    $body = "===== 关键行 (带上下文, " + $r.keyLines + " 行 / 原文 " + $r.origLines + " 行) =====`n" + $r.key + "`n`n===== 尾部 " + [Math]::Min(1500, $r.origLines) + " 行 (连续重复已压缩) =====`n" + $r.tail
    Write-DiagFile $f "重启后 dmesg (摘要)" $body "若与 02_pstore 同时存在, 以 pstore 为 panic 主证据"
  }
  $files += New-DiagEntry $OutDir "04_dmesg.txt" "重启后 dmesg (尾部+关键行摘要)"

  # ---- 05_mtk_aee: MTK 异常库目录清单 (仅清单, 不拉全树避免噪音) ----
  $aeeDir = Join-Path $OutDir "05_mtk_aee"
  New-Item -ItemType Directory -Force -Path $aeeDir | Out-Null
  foreach ($p in @("/data/aee_exp", "/data/vendor/log/aee_exp",
      "/sdcard/mtklog", "/data/vendor/log/mtklog", "/data/vendor/log")) {
    $fn = ($p -replace '[^\w\.\-]', '_')
    $ls = AdbSh ("ls -la " + $p + " 2>&1")
    if (-not [string]::IsNullOrEmpty($ls)) {
      Write-DiagFile (Join-Path $aeeDir ($fn + ".txt")) ("AEE/日志目录清单: " + $p) $ls
    }
  }
  $files += New-DiagEntry $OutDir "05_mtk_aee" "MTK AEE/mtklog 目录清单 (权限允许时可进一步拉取)"

  # ---- 06_local_tmp: panic 前最后动作 (运行标记/glt/w2 日志, 限量防噪音) ----
  $tmpDir = Join-Path $OutDir "06_local_tmp"
  New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
  $tmpNames = @((AdbSh "ls /data/local/tmp/ 2>/dev/null") -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  foreach ($n in $tmpNames) {
    if ($n -match '^(glt_seq_|w2h_|w2dbg_|w2cred_|rootproof_|dmesg_pre_|run\.sh$|w\.log$|rootcmd_|diag_root_)') {
      if ($n -match '\.sock$') { continue }   # socket 文件无内容, 跳过
      $safe = ($n -replace '[^\w\.\-]', '_')
      if ($n -match '^diag_root_') {
        # root 级日志快照目录 (STAGE6 有权限时 dump): 逐文件读取
        $sub = @((AdbSh ("ls /data/local/tmp/" + $n + "/ 2>/dev/null")) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach ($sn in $sub) {
          $content = AdbSh ("cat /data/local/tmp/" + $n + "/" + $sn + " 2>&1")
          if ($sn -match '^dmesg') {
            # root 快照的 dmesg 可能 4MB+, 同样做尾部+关键行摘要
            $r = Reduce-DiagText $content 1500 2
            $body = "===== 关键行 (带上下文, " + $r.keyLines + " 行 / 原文 " + $r.origLines + " 行) =====`n" + $r.key + "`n`n===== 尾部 " + [Math]::Min(1500, $r.origLines) + " 行 (连续重复已压缩) =====`n" + $r.tail
            Write-DiagFile (Join-Path $tmpDir ($safe + "_" + $sn)) ("root 级日志: " + $sn + " (摘要)") $body "STAGE6 root 权限阶段 dump, dmesg 已摘要"
          } else {
            Write-DiagFile (Join-Path $tmpDir ($safe + "_" + $sn)) ("root 级日志: " + $sn) $content "STAGE6 root 权限阶段 dump (kernel logcat/模块/selinux)"
          }
        }
      } else {
        $cmd = if ($n -match '\.(log|txt)$') { ("tail -n 2000 /data/local/tmp/" + $n + " 2>&1") } else { ("cat /data/local/tmp/" + $n + " 2>&1") }
        $content = AdbSh $cmd
        Write-DiagFile (Join-Path $tmpDir $safe) ("设备侧运行残留: " + $n) $content "glt_seq_* 的最后一条记录 = panic 前最后动作; *.log 仅保留末尾 2000 行"
      }
    }
  }
  $files += New-DiagEntry $OutDir "06_local_tmp" "panic 前最后动作标记 / glt/w2host 日志 / root 级快照 (限量)"

  # ---- 07/08 logcat: 只抓 crash 缓冲 + main 尾部 300 行 ----
  $f = Join-Path $OutDir "07_logcat_crash.txt"
  Write-DiagFile $f "重启后 logcat crash 缓冲" (AdbSh "logcat -b crash -d -v threadtime 2>&1") "重启后缓冲已清空, 通常为空"
  $files += New-DiagEntry $OutDir "07_logcat_crash.txt" "logcat crash 缓冲"
  $f = Join-Path $OutDir "08_logcat_main_tail300.txt"
  Write-DiagFile $f "重启后 logcat main 尾部 300 行" (AdbSh "logcat -b main -d -t 300 -v threadtime 2>&1") "仅尾部, 观察启动崩溃/关键错误"
  $files += New-DiagEntry $OutDir "08_logcat_main_tail300.txt" "logcat main 尾部 300 行"

  # ---- 99_READ_ME.txt: 给 AI/维护者的阅读指南 ----
  $guide = @(
    "本 zip 由 GhostLock-X200 root.ps1 自动采集 (mode=${Mode}: panic=异常重启后 / failure=未重启现场)。",
    "所有 .txt 文件均为 UTF-8 纯文本, 前 4 行为文件头注释 (file/内容/采集时间/备注)。",
    "大文件 (dmesg/pstore) 已压缩为「尾部+关键行」摘要: L<行号> 对应原文行号,",
    "连续重复行已折叠为 (xN) 形式; 关键信息 (panic 栈/错误) 在关键行与尾部均完整保留。",
    "采集为只读命令且仅在主链退出后执行, 不会引发 panic。",
    "",
    "推荐分析顺序:",
    "  0) 00_SUMMARY.txt     -> AI 速读摘要 (设备/失败阶段/最后动作/panic 证据/结论), 优先阅读",
    "  1) 00_manifest.json  -> 机器可读索引 (设备/内核/启动原因/文件清单+用途)",
    "  2) 01_boot_info.txt  -> 确认机型/系统/内核构建与启动原因; kernel.build_hash 与工具预期不一致 = 机型不兼容高概率",
    "  3) 02_pstore/*       -> panic 瞬间内核日志 (最关键): 在 dmesg-ramoops-0/console-ramoops-0 尾部查找",
    "                          'Kernel panic - not syncing' / 'Call trace:' / 'CPU: <n> PID:' 定位崩溃栈与触发点",
    "  4) 06_local_tmp/glt_seq_*.txt -> 最后一条 'WRITE cand=... gl5=...' 记录 = panic 前最后一次写操作",
    "  5) 06_local_tmp/*.log -> glt/w2host 运行输出; 06_local_tmp/diag_root_* 为 STAGE6 root 阶段快照",
    "  6) 98_main_chain.log / 97_root_console.log -> host 侧完整运行记录, 定位失败/panic 发生阶段",
    "  7) 05_mtk_aee/*      -> MTK AEE 异常库清单 (如需完整 db 需 root 另抓)",
    "",
    "判读线索:",
    "  - 02_pstore 有 dmesg-ramoops-0 且含 panic 栈      -> 内核 panic, 触发点见 06_local_tmp/glt_seq_*",
    "  - bootreason 含 'watchdog'/'wdt'                 -> 看门狗复位 (卡死/软锁), 同样看 glt_seq_*",
    "  - 01_boot_info kernel.build_hash != 预期 $expectedKernel -> 内核不匹配, 极可能机型/系统版本不兼容",
    "  - 06_local_tmp 缺失 glt_seq_*                    -> panic 发生在更早阶段, 结合 98_main_chain.log 定位",
    "",
    "非支持机型说明: 本工具官方仅支持预期内核构建的机型; 其他机型仅可用于排查, root 需二次开发适配。"
  )
  $f = Join-Path $OutDir "99_READ_ME.txt"
  $guide | Out-File -FilePath $f -Encoding utf8
  $files += New-DiagEntry $OutDir "99_READ_ME.txt" "阅读指南 (分析顺序与判读线索)"

  # ---- 00_manifest.json / 00_manifest.txt: 机器可读索引 ----
  $reason = Get-BootReasonNow
  $panicLikely = if ($reason -match 'panic|wdt|watchdog') { "内核 panic 或看门狗复位 (需结合 02_pstore 确认)" } else { "异常重启, 原因待确认" }
  $manifest = [ordered]@{
    tool          = "GhostLock-X200 root.ps1"
    version       = "v1.3.0"
    collect_time  = $now
    mode          = $Mode
    device        = [ordered]@{
      brand                = (AdbSh "getprop ro.product.brand")
      model                = (AdbSh "getprop ro.product.model")
      build                = (AdbSh "getprop ro.build.display.id")
      sdk                  = (AdbSh "getprop ro.build.version.sdk")
      kernel_version       = $kv
      kernel_build_hash    = (Get-BuildHash $kv)
      expected_kernel_build = $expectedKernel
    }
    boot          = [ordered]@{
      reason_raw   = $reason
      panic_likely = $panicLikely
      boot_id      = (Get-BootIdNow)
    }
    files         = $files
  }
  $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $OutDir "00_manifest.json") -Encoding utf8
  $mtxt = @()
  $mtxt += ("tool=" + $manifest.tool + " version=" + $manifest.version + " mode=" + $manifest.mode + " collect_time=" + $manifest.collect_time)
  $mtxt += ("device.brand=" + $manifest.device.brand)
  $mtxt += ("device.model=" + $manifest.device.model)
  $mtxt += ("device.build=" + $manifest.device.build)
  $mtxt += ("device.sdk=" + $manifest.device.sdk)
  $mtxt += ("device.kernel_version=" + $manifest.device.kernel_version)
  $mtxt += ("device.kernel_build_hash=" + $manifest.device.kernel_build_hash + " expected=" + $manifest.device.expected_kernel_build)
  $mtxt += ("boot.reason_raw=" + $manifest.boot.reason_raw)
  $mtxt += ("boot.panic_likely=" + $manifest.boot.panic_likely)
  $mtxt += ("boot.boot_id=" + $manifest.boot.boot_id)
  $mtxt += ("files: " + (($manifest.files | ForEach-Object { $_.name + "(" + $_.size + "B:" + $_.note + ")" }) -join "; "))
  $mtxt | Out-File -FilePath (Join-Path $OutDir "00_manifest.txt") -Encoding utf8
  $files += New-DiagEntry $OutDir "00_manifest.json" "机器可读索引 (JSON)"
  $files += New-DiagEntry $OutDir "00_manifest.txt" "索引 (人可读)"

  return $manifest
}

function Show-PanicGuide {
  param([string]$ZipPath, $Manifest, [string]$Mode = "failure")
  if ($Mode -eq "panic") { SayErr "检测到设备异常重启 (内核 panic 或 watchdog 重启)。" }
  elseif ($Mode -eq "offline") { SayErr "主链执行失败且设备长时间未恢复 (可能关机/未开启调试)。已保存 host 侧日志。" }
  else { SayErr "主链执行失败 (设备未重启), 已采集现场诊断日志。" }
  Say "==================== 诊断摘要 (可直接粘贴给 Agent) ===================="
  Say ("tool=" + $Manifest.tool + " version=" + $Manifest.version + " mode=" + $Mode + " collect_time=" + $Manifest.collect_time)
  Say ("device.brand=" + $Manifest.device.brand + " model=" + $Manifest.device.model)
  Say ("device.build=" + $Manifest.device.build + " sdk=" + $Manifest.device.sdk)
  Say ("device.kernel_version=" + $Manifest.device.kernel_version)
  Say ("device.kernel_build_hash=" + $Manifest.device.kernel_build_hash + " expected=" + $Manifest.device.expected_kernel_build)
  Say ("boot.reason_raw=" + $Manifest.boot.reason_raw)
  Say ("boot.panic_likely=" + $Manifest.boot.panic_likely)
  Say ("diag_zip=" + $ZipPath)
  Say "========================================================================"
  if ($Manifest.device.kernel_build_hash -and $Manifest.device.kernel_build_hash -ne $Manifest.device.expected_kernel_build) {
    SayErr "当前内核构建与工具预期不一致, 极可能机型/系统版本不兼容导致 panic; 此工具官方仅支持预期内核构建的机型。"
  }
  SayOk "诊断日志已就绪: $ZipPath"
  Say "请将该 zip 文件 (连同上方诊断摘要) 发送给维护者/Agent 分析。"
  Say "优先阅读 zip 内 00_SUMMARY.txt (AI 速读摘要); 01_boot_info 看机型/内核; 02_pstore/ 看 panic 栈; 06_local_tmp/glt_seq_*.txt 看最后动作。"
}

# ============================================================
# MAIN
# ============================================================
Say "=============================================="
Say " GhostLock-X200 一键 Root (v1.3.0)"
Say "=============================================="

# 0. 依赖自检 (adb + python 依赖; -SkipDeps 跳过自动下载)
$adb = Ensure-Adb
if (-not $adb) { exit 1 }
$env:ANDROID_ADB = $adb   # 透传给主链子进程 (主链优先用此路径)
$python = Ensure-PythonDeps
if (-not $python) { exit 1 }
SayOk "adb: $adb"
SayOk "python: $python"

# 2. 设备
$serial = $Serial
if (-not $serial) { $serial = $env:ANDROID_SERIAL }
if (-not $serial) {
  $devs = @(& $adb devices 2>$null | Select-String "`tdevice$" | ForEach-Object { ($_ -split "`t")[0] })
  if ($devs.Count -eq 1) { $serial = $devs[0] }
  elseif ($devs.Count -gt 1) {
    # 同一物理设备可能 USB + 无线双连接 (如 10AEAC39B7000QN + 192.168.x.x:5555):
    # 按 ro.serialno 去重, 唯一则自动选用 (优先 USB, 其次第一个)
    $uniq = @{}
    $pick = $null
    foreach ($d in $devs) {
      $phys = (& $adb -s $d shell getprop ro.serialno 2>$null | Out-String).Trim()
      if (-not $phys) { $phys = $d }
      if (-not $uniq.ContainsKey($phys)) {
        $uniq[$phys] = $d
        # 优先 USB (无 :port 后缀); 无线仅在无 USB 时兜底
        if ($d -notmatch ':\d+$') { $pick = $d }
        if (-not $pick) { $pick = $d }
      }
    }
    if ($uniq.Count -eq 1) {
      $serial = $pick
      SayWarn "检测到同一设备的多个连接 (USB + 无线), 自动选用: $serial"
    } else {
      SayErr "检测到多台设备, 请用 -Serial 指定: $($devs -join ', ')"
      exit 1
    }
  }
  else { SayErr "未检测到设备, 请连接手机并开启 USB 调试/无线调试"; exit 1 }
}
SayOk "设备: $serial"

# 3. build 检测 + 机型模块自动匹配 (v1.4)
$ver = (& $adb -s $serial shell cat /proc/version 2>$null | Out-String).Trim()
Say "内核版本: $($ver.Split([Environment]::NewLine)[0])"
$modMatch = Match-DeviceModule $ver

if ($Force) {
  SayWarn "-Force: 跳过机型匹配, 强制使用 $ProfilePath 直接运行 (偏移不匹配有 panic 风险, 风险自担!)"
} elseif ($modMatch -and $modMatch.level -eq "exact") {
  $ProfilePath = $modMatch.path
  $ProfileInfo = $modMatch.device
  SayOk ("机型模块命中 (exact): " + $ProfileInfo.device + " -> " + $ProfilePath)
  $mo = Join-Path (Split-Path $ProfilePath) "win_offs.json"
  if (Test-Path -LiteralPath $mo) {
    $GEN_WIN_OFFS = $mo
    SayOk "使用模块偏移: $GEN_WIN_OFFS"
  } else {
    SayWarn "模块命中但缺 win_offs.json, 需从素材重建偏移"
    $work = Join-Path $env:TEMP "ghostlock_offsets"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $asset = Choose-Asset
    $rebuild = Invoke-DeviceBuild -Asset $asset -WorkDir $work
    if ($null -eq $rebuild) { SayErr "机型模块生成失败"; exit 1 }
    if ($rebuild -eq "cancelled") { SayErr "已取消"; exit 1 }
  }
} else {
  if ($modMatch) {
    SayWarn ("同族模块命中 (family): " + $modMatch.device.device + " 未精确匹配, 需重新生成偏移")
  } else {
    SayWarn "未匹配到机型模块, 将自动提取并生成新机型模块 (可分享)。"
  }
  Say "本工具可自动从 全量包 zip / payload.bin / boot.img / kernel.raw / kernel.elf 重建 win_offs。"
  $work = Join-Path $env:TEMP "ghostlock_offsets"
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $asset = Choose-Asset

  # 1. 机型可行性预检 (先摆上台面: 避免在 MTK 未知族 / init_boot 误选上空耗)
  $oa = Join-Path $pkgRoot "tools\offset_tools\offsets_auto.py"
  $feasOut = (& $python $oa feasibility $asset --profile $ProfilePath 2>&1 | Out-String)
  Log-Raw ("[feasibility]`n" + $feasOut)
  @($feasOut -split "`r?`n") | ForEach-Object { if ($_.Trim()) { Say $_ } }
  if ($feasOut -match "预检结论: 不推荐") {
    $resp = Read-Host "预检结论: 不推荐 (原因见上方)。是否仍要继续? (y/N)"
    if ($resp -notmatch '^[yY]') { SayErr "已取消, 未生成偏移"; exit 1 }
  }

  # 2. 新机型偏移重建 (v1.6: package 主导 + KMI 自动 + prebuilt 门禁, 无需 vmlinux-to-elf)
  $rebuild = Invoke-DeviceBuild -Asset $asset -WorkDir $work
  if ($null -eq $rebuild) { SayErr "机型模块生成失败, 请检查素材/依赖后重试"; exit 1 }
  if ($rebuild -eq "cancelled") { SayErr "已取消"; exit 1 }
  SayOk "将使用新偏移: $GEN_WIN_OFFS"
}

# 记录运行前 boot_id, 用于主链失败后判断设备是否异常重启
$bootIdBefore = (Get-BootIdNow)

# 4. 调用主链
$main = Join-Path $pkgRoot "tools\scripts\root_full_permissive_restore.ps1"
$argsMain = @("-File", $main)
if ($AdbPath) { $argsMain += @("-AdbPath", $AdbPath) }
if ($Serial)  { $argsMain += @("-Serial", $Serial) }
if ($KO_ADAPTED) { $argsMain += @("-KsuKoPath", $KO_ADAPTED) }
elseif ($KsuKoPath) { $argsMain += @("-KsuKoPath", $KsuKoPath) }
if ($PR_ADAPTED) { $argsMain += @("-PermRestorePath", $PR_ADAPTED) }
if ($ModuleW2) { $argsMain += @("-W2HostPath", $ModuleW2) }
if ($ModuleGlt) { $argsMain += @("-GltPath", $ModuleGlt) }
if ($GEN_WIN_OFFS) { $argsMain += @("-WinOffsPath", $GEN_WIN_OFFS) }
if ($ProfilePath) { $argsMain += @("-ProfilePath", $ProfilePath) }
if ($SkipPermissiveRestore) { $argsMain += "-SkipPermissiveRestore" }

Say "=============================================="
Say "调用主链: $main"
Say "参数: $($argsMain -join ' ')"
Say "=============================================="
# Tee 同时输出到控制台并完整捕获主链输出 (各阶段/报错, 判断失败发生在哪一阶段)
$mainOutTee = $null
& powershell -NoProfile -ExecutionPolicy Bypass $argsMain 2>&1 | Tee-Object -Variable mainOutTee
$rc = $LASTEXITCODE
$mainOutput = ""
if ($mainOutTee) {
  $mainOutput = (($mainOutTee | Out-String) -replace "`r?`n$", "")
  Log-Raw ("[主链输出]`n" + $mainOutput)
}

# 5.0 主链成功后: 自动尝试获取 P0 物理常量 (detect-p0, 需设备临时 su; 失败静默)
if ($rc -eq 0) {
  Say "主链成功。尝试自动获取 P0 物理常量 (detect-p0, 需设备临时 su; 失败不影响) ..."
  $p0Log = (& $python $oa detect-p0 2>&1 | Out-String)
  Log-Raw ("[detect-p0]`n" + $p0Log)
  if ($p0Log -match "p0_phys_offset") {
    @($p0Log -split "`r?`n" | Where-Object { $_.Trim() }) | ForEach-Object { Say $_ }
    Say "如需固化到模块: python tools\offset_tools\offsets_auto.py detect-p0 --write-profile `"$ProfilePath`""
  } else {
    SayWarn "detect-p0 未成功 (设备 devicetree 不可读且无 su iomem; 不影响本次 root, 可后续手动补齐)"
  }
}

# 5. 失败路径: 自动采集诊断日志 (默认开启; -NoPanicDiag 关闭)
#    采集只读、仅在主链退出后执行, 不会引发 panic; 内容面向 AI/维护者分析.
if ($rc -ne 0 -and -not $NoPanicDiag) {
  $mode = "failure"
  if (-not (Get-DeviceOnline)) {
    Say "设备当前离线, 等待重启完成 (最长 12 分钟)..."
    if (Wait-DeviceOnline) {
      $bidNow = Get-BootIdNow
      if ($bidNow -and $bootIdBefore -and $bidNow -ne $bootIdBefore) { $mode = "panic" }
    } else {
      $mode = "offline"; SayErr "设备长时间未恢复, 请手动确认手机状态 (诊断仍会保存 host 侧日志)"
    }
  } else {
    $bidNow = Get-BootIdNow
    if ($bidNow -and $bootIdBefore -and $bidNow -ne $bootIdBefore) { $mode = "panic" }
  }

  if ($mode -eq "panic") { SayWarn "检测到异常重启 (panic/watchdog), 自动采集诊断日志 ..." }
  else { SayWarn "主链失败 (退出码 $rc) 但设备未重启, 自动采集现场诊断日志 ..." }

  $ts = Get-Date -Format "yyyyMMdd_HHmmss"
  $diagDir = Join-Path $env:TEMP ("ghostlock_diag_" + $ts)
  Say "采集目录: $diagDir"
  $manifest = Collect-PanicDiag $diagDir -Mode $mode

  # 附上主链完整输出 (各阶段/报错) 与 root.ps1 自身日志
  if ($mainOutput) {
    $f98 = Join-Path $diagDir "98_main_chain.log"
    $mainOutput | Out-File -FilePath $f98 -Encoding utf8
    $manifest.files += @{ name = "98_main_chain.log"; size = (Get-Item $f98).Length; note = "主链完整输出 (各阶段/报错, 定位失败阶段)" }
  }
  if ($LOG_FILE -and (Test-Path -LiteralPath $LOG_FILE)) {
    Copy-Item -LiteralPath $LOG_FILE (Join-Path $diagDir "97_root_console.log") -Force
    $manifest.files += @{ name = "97_root_console.log"; size = (Get-Item (Join-Path $diagDir "97_root_console.log")).Length; note = "root.ps1 自身运行日志" }
  }
  # AI 速读摘要 (00_SUMMARY.txt) + 98/97 已追加 -> 重写索引, 保持 manifest 与 zip 一致
  $summary = Build-DiagSummary $manifest $diagDir $mainOutput
  $summary | Out-File -FilePath (Join-Path $diagDir "00_SUMMARY.txt") -Encoding utf8
  $manifest.files += @{ name = "00_SUMMARY.txt"; size = (Get-Item (Join-Path $diagDir "00_SUMMARY.txt")).Length; note = "AI 速读摘要 (优先阅读/可直接粘贴给 Agent)" }
  $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $diagDir "00_manifest.json") -Encoding utf8
  "附加: 00_SUMMARY.txt (AI 速读摘要) / 98_main_chain.log / 97_root_console.log (host 侧完整日志)" | Out-File -FilePath (Join-Path $diagDir "00_manifest.txt") -Encoding utf8 -Append

  $zip = Join-Path $pkgRoot ("log\ghostlock_diag_" + $ts + ".zip")
  try {
    Compress-Archive -Path (Join-Path $diagDir "*") -DestinationPath $zip -Force
  } catch {
    $zip = Join-Path $env:TEMP ("ghostlock_diag_" + $ts + ".zip")
    Compress-Archive -Path (Join-Path $diagDir "*") -DestinationPath $zip -Force
  }
  if (-not (Test-Path -LiteralPath $zip)) {
    SayErr "诊断日志打包失败, 原始目录保留在: $diagDir (可直接打包该目录发送)"
    $zip = $diagDir
  }
  Show-PanicGuide $zip $manifest $mode
} elseif ($rc -ne 0) {
  SayErr "-NoPanicDiag: 未采集诊断; 如需分析请发送运行日志: $LOG_FILE"
}
if ($LOG_FILE -and (Test-Path -LiteralPath $LOG_FILE)) { SayOk "运行日志已保存: $LOG_FILE" }
exit $rc
