# ============================================================
# find_adb.ps1 - 智能 adb 定位 (供 root.ps1 与主链共用)
# 探测顺序: 显式指定 > 环境变量 > PATH > 常见安装位置 (含 SDK/包内/依赖目录)
#          > 有界递归搜索; 每个候选都用 `adb version` 校验可用性,
#          跳过残缺/0 字节/非官方文件, 避免"找到但跑不起来".
# 说明: `adb version` 不会启动 adb server, 无副作用.
# ============================================================

function Test-AdbWorking {
  param([string]$Path)
  if (-not $Path) { return $false }
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  try {
    $v = (& $Path version 2>&1 | Out-String)
    return ($v -match 'Android Debug Bridge version')
  } catch { return $false }
}

function Get-AdbPath {
  param(
    [string]$Preferred,          # 显式指定 (-AdbPath), 存在即返回
    [string]$PackageRoot,        # 包根目录 (查包内 platform-tools/, 离线包场景)
    [string[]]$ExtraCandidates   # 额外候选 (依赖目录等, 由调用方提供)
  )
  $cands = @()

  # 1) 显式指定
  if ($Preferred) { if (Test-AdbWorking $Preferred) { return $Preferred } }

  # 2) 环境变量
  foreach ($ev in @('ANDROID_ADB', 'ADB_PATH')) {
    $v = [Environment]::GetEnvironmentVariable($ev)
    if ($v -and (Test-AdbWorking $v)) { return $v }
  }

  # 3) PATH
  $cmd = Get-Command adb -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.Source -and (Test-AdbWorking $cmd.Source)) { return $cmd.Source }

  # 4) 常见安装位置
  $cands += @(
    "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
    "$env:ANDROID_HOME\platform-tools\adb.exe",
    "$env:ANDROID_SDK_ROOT\platform-tools\adb.exe",
    "$env:USERPROFILE\scoop\apps\platform-tools\current\adb.exe",
    "$env:USERPROFILE\scoop\shims\adb.exe",
    "C:\ProgramData\chocolatey\bin\adb.exe",
    "C:\Program Files\platform-tools\adb.exe",
    "C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe",
    "C:\Android\platform-tools\adb.exe",
    "C:\adb\adb.exe",
    "C:\platform-tools\adb.exe",
    "D:\Android\platform-tools\adb.exe",
    "D:\adb\adb.exe",
    "$env:USERPROFILE\.android\platform-tools\adb.exe"
  )
  # 包内 (离线包把 platform-tools 放包根)
  if ($PackageRoot) {
    $cands += @(
      (Join-Path $PackageRoot "platform-tools\adb.exe"),
      (Join-Path $PackageRoot "tools\platform-tools\adb.exe"),
      (Join-Path $PackageRoot "tools\adb\adb.exe")
    )
  }
  # 调用方补充 (依赖下载目录等)
  if ($ExtraCandidates) { $cands += $ExtraCandidates }

  foreach ($c in $cands) {
    if ($c -and (Test-AdbWorking $c)) { return $c }
  }

  # 5) 有界递归搜索 (深度受限, 只扫常见根, 找到第一个可用即停)
  $roots = @(
    "$env:LOCALAPPDATA\Android",
    "$env:LOCALAPPDATA\Microsoft\WinGet\Packages",
    "$env:USERPROFILE\AppData\Local\Programs",
    "$env:USERPROFILE\Downloads",
    "C:\Android", "C:\adb", "C:\tools", "C:\platform-tools"
  )
  foreach ($root in $roots) {
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
    $hit = Get-ChildItem -LiteralPath $root -Filter adb.exe -File -Recurse -Depth 4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit -and (Test-AdbWorking $hit.FullName)) { return $hit.FullName }
  }

  return $null
}
