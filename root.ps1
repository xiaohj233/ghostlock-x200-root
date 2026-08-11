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
#   powershell -ExecutionPolicy Bypass -File root.ps1 -DepsInPackage  # 依赖下载到项目根目录 (打包发布用)
# 自动依赖下载 (开箱即用, 写入 %LOCALAPPDATA%\GhostLock-X200\deps, 不进仓库):
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
  [string]$DepsDir,        # 依赖下载目录 (默认 %LOCALAPPDATA%\GhostLock-X200\deps; 可指定项目根目录打包)
  [switch]$DepsInPackage,  # 依赖下载到项目根目录 (等价 -DepsDir <包根>; 发布离线包用)
  [switch]$NoLog,          # 不写日志 (默认每次自动写 %TEMP%\ghostlock_root_<时间戳>.log)
  [string]$LogPath,        # 日志文件路径 (默认 %TEMP%\ghostlock_root_<时间戳>.log)
  [switch]$NoPanicDiag     # 主链失败后不自动采集 panic 诊断日志 (默认开启)
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
$EXPECTED_KERNEL = "b57af212129c"
$KERNEL_ELF_PAT  = $null   # 本次生成/找到的 kernel ELF
$GEN_WIN_OFFS    = $null   # 本次生成的 win_offs json

# ---------- 日志 (默认开启: 所有 Say*/子进程输出统一落盘; -NoLog 关闭) ----------
$LOG_FILE = $null
if (-not $NoLog) {
  if (-not $LogPath) { $LogPath = Join-Path $env:TEMP ("ghostlock_root_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log") }
  try {
    $logDir = Split-Path $LogPath -Parent
    if (-not $logDir) { $logDir = (Get-Location).Path }
    if ($logDir) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
    $LOG_FILE = (Resolve-Path $logDir).Path + "\" + (Split-Path $LogPath -Leaf)
    "" | Out-File -FilePath $LOG_FILE -Encoding utf8
  } catch { $LOG_FILE = $null }
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
  if ($ext -eq ".img") { return "bootimg" }
  if ($ext -eq ".bin") { return "payload" }
  if ($ext -eq ".elf") { return "kernel_elf" }
  if ($ext -eq ".raw") { return "kernel_raw" }
  return "unknown"
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
  $dep = Get-DepsDir
  foreach ($cand in @(
      (Join-Path $dep "payload-dumper-go\payload-dumper-go.exe"),
      (Join-Path $dep "payload-dumper-go\payload-dumper-go"))) {
    if (Test-Path $cand) { return @{ type="go"; cmd=$cand } }
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
  # 优先级: -DepsDir 显式指定 > -DepsInPackage (项目根目录) > 默认 %LOCALAPPDATA% 旧位置 (兼容)
  if ($DepsDir) { $d = $DepsDir }
  elseif ($DepsInPackage) { $d = $pkgRoot }
  else { $d = Join-Path $env:LOCALAPPDATA "GhostLock-X200\deps" }
  New-Item -ItemType Directory -Force -Path $d | Out-Null
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
  $output = (& $py $oa winoffs $Elf $out 2>&1 | Out-String)
  Pop-Location
  Log-Raw ("[winoffs]`n" + $output)
  @($output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 3) | ForEach-Object { Say "winoffs: $_" }
  if (-not (Test-Path $out)) { SayErr "offsets_auto.py winoffs 失败 (无输出)"; Show-Tail $output; return $null }
  SayOk "win_offs 已生成: $out"
  return $out
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

function Collect-PanicDiag {
  param([string]$OutDir, [string]$Mode = "failure")   # Mode: panic=异常重启后采集 / failure=未重启现场采集
  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $files = @()

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
    $safe = ($n -replace '[^\w\.\-]', '_')
    $content = AdbSh ("cat /sys/fs/pstore/" + $n + " 2>&1")
    Write-DiagFile (Join-Path $psDir $safe) ("pstore: " + $n) $content
  }
  $files += New-DiagEntry $OutDir "02_pstore" "panic 瞬间内核日志 (dmesg-ramoops-*/console-ramoops-*); listing.txt 记录可读性"

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
    Write-DiagFile $f "重启后 dmesg" $dm "若与 02_pstore 同时存在, 以 pstore 为 panic 主证据"
  }
  $files += New-DiagEntry $OutDir "04_dmesg.txt" "重启后 dmesg 尝试"

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
      $safe = ($n -replace '[^\w\.\-]', '_')
      if ($n -match '^diag_root_') {
        # root 级日志快照目录 (STAGE6 有权限时 dump): 逐文件读取
        $sub = @((AdbSh ("ls /data/local/tmp/" + $n + "/ 2>/dev/null")) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        foreach ($sn in $sub) {
          $content = AdbSh ("cat /data/local/tmp/" + $n + "/" + $sn + " 2>&1")
          Write-DiagFile (Join-Path $tmpDir ($safe + "_" + $sn)) ("root 级日志: " + $sn) $content "STAGE6 root 权限阶段 dump (dmesg/kernel logcat/模块/selinux)"
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
    "采集为只读命令且仅在主链退出后执行, 不会引发 panic。",
    "",
    "推荐分析顺序:",
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
    "  - 01_boot_info kernel.build_hash != 预期 b57af212129c -> 内核不匹配, 极可能机型/系统版本不兼容",
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
    version       = "v1.1.0"
    collect_time  = $now
    mode          = $Mode
    device        = [ordered]@{
      brand                = (AdbSh "getprop ro.product.brand")
      model                = (AdbSh "getprop ro.product.model")
      build                = (AdbSh "getprop ro.build.display.id")
      sdk                  = (AdbSh "getprop ro.build.version.sdk")
      kernel_version       = $kv
      kernel_build_hash    = (Get-BuildHash $kv)
      expected_kernel_build = "b57af212129c"
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
  Say "分析提示: 01_boot_info.txt 看机型/内核; 02_pstore/ 尾部看 panic 调用栈; 06_local_tmp/glt_seq_*.txt 最后一条记录定位 panic 前动作。"
}

# ============================================================
# MAIN
# ============================================================
Say "=============================================="
Say " GhostLock-X200 一键 Root (v1.1.0)"
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
  elseif ($devs.Count -gt 1) { SayErr "检测到多台设备, 请用 -Serial 指定: $($devs -join ', ')"; exit 1 }
  else { SayErr "未检测到设备, 请连接手机并开启 USB 调试/无线调试"; exit 1 }
}
SayOk "设备: $serial"

# 3. build 检测
$ver = (& $adb -s $serial shell cat /proc/version 2>$null | Out-String).Trim()
Say "内核版本: $($ver.Split([Environment]::NewLine)[0])"
$buildMatch = $ver -match $EXPECTED_KERNEL

if ($Force) {
  SayWarn "-Force: 跳过 build 检测, 强制使用随包 b57 偏移直接运行 (非 b57 build 有 panic 风险, 风险自担!)"
} elseif ($buildMatch) {
  SayOk "内核与随包偏移匹配 (b57), 直接运行主链"
} else {
  SayWarn "内核与随包 b57 偏移不匹配或无法确认。需要重新生成偏移。"
  Say "本工具可自动从 全量包 zip / payload.bin / boot.img / kernel.raw / kernel.elf 重建 win_offs。"
  $work = Join-Path $env:TEMP "ghostlock_offsets"
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $asset = Choose-Asset
  $wo = Build-WinOffsFromAsset $asset $work
  if (-not $wo) { SayErr "偏移生成失败, 请按提示补齐工具或素材后重试"; exit 1 }
  $GEN_WIN_OFFS = $wo
  SayOk "将使用新偏移: $GEN_WIN_OFFS"
}

# 记录运行前 boot_id, 用于主链失败后判断设备是否异常重启
$bootIdBefore = (Get-BootIdNow)

# 4. 调用主链
$main = Join-Path $pkgRoot "tools\scripts\root_full_permissive_restore.ps1"
$argsMain = @("-File", $main)
if ($AdbPath) { $argsMain += @("-AdbPath", $AdbPath) }
if ($Serial)  { $argsMain += @("-Serial", $Serial) }
if ($KsuKoPath) { $argsMain += @("-KsuKoPath", $KsuKoPath) }
if ($GEN_WIN_OFFS) { $argsMain += @("-WinOffsPath", $GEN_WIN_OFFS) }
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
  # 98/97 已追加 -> 重写索引, 保持 manifest 与 zip 内容一致 (AI 可读性)
  $manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $diagDir "00_manifest.json") -Encoding utf8
  "附加: 98_main_chain.log / 97_root_console.log (host 侧完整日志, 定位失败阶段)" | Out-File -FilePath (Join-Path $diagDir "00_manifest.txt") -Encoding utf8 -Append

  $zip = Join-Path (Get-Location).Path ("ghostlock_diag_" + $ts + ".zip")
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
exit $rc
