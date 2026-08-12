@echo off
setlocal
rem ============================================================
rem  GhostLock-X200: single double-click entry (ASCII-only to
rem  stay safe under any cmd codepage; keep this file CRLF).
rem  - runs root.ps1, keeps window open (errors stay visible)
rem  - logs: log\ghostlock_root_<timestamp>.log
rem    panic diag bundle: log\ghostlock_diag_<timestamp>.zip
rem  - extra args are passed through, e.g.:
rem    run_root.bat -AssetPath C:\path\boot.img
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
