@echo off
setlocal
rem ============================================================
rem  GhostLock-X200: 唯一双击入口
rem  - 运行 root.ps1, 结束后窗口停留 (报错不闪没)
rem  - 日志自动写入 log\ 文件夹: log\ghostlock_root_<时间戳>.log
rem    异常重启诊断包: log\ghostlock_diag_<时间戳>.zip
rem  - 可选参数透传, 如: run_root.bat -AssetPath C:\path\boot.img
rem ============================================================
cd /d "%~dp0"
echo Starting GhostLock-X200 root.ps1 ...
echo Log folder: %~dp0log
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0root.ps1" %*
echo.
echo ============================================
echo Finished. Errors (if any) are shown above.
echo Log saved to: %~dp0log
echo Press any key to close this window.
pause >nul
