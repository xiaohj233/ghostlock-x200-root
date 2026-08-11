@echo off
setlocal
rem ============================================================
rem  GhostLock-X200: run root.ps1 with full logging
rem  Works with OLD releases too (no -Log support needed).
rem  Usage: double-click this file (place it next to root.ps1)
rem  Log:   %USERPROFILE%\Desktop\ghostlock_log.txt
rem ============================================================
set "GHOSTLOCK_DIR=%~dp0"
set "GHOSTLOCK_LOG=%USERPROFILE%\Desktop\ghostlock_log.txt"
echo Running root.ps1 ...
echo Log file: %GHOSTLOCK_LOG%
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Transcript -LiteralPath $env:GHOSTLOCK_LOG -Force | Out-Null } catch { Write-Host ('[!] cannot start transcript: ' + $_.Exception.Message) }; try { & (Join-Path $env:GHOSTLOCK_DIR 'root.ps1') } catch { Write-Host ('[X] EXCEPTION: ' + $_.Exception.Message) -ForegroundColor Red } finally { try { Stop-Transcript | Out-Null } catch {} }"
echo.
echo Finished. Log saved to: %GHOSTLOCK_LOG%
echo Please send this log file to the maintainer.
pause
