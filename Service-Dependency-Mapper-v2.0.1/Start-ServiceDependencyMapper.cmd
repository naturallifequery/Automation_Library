@echo off
setlocal
set "SDM_ROOT=%~dp0"

where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo Windows PowerShell was not found.
  echo Service Dependency Mapper requires Windows PowerShell 5.1.
  pause
  exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File "%SDM_ROOT%ServiceDependencyMapper.ps1"
if errorlevel 1 (
  echo.
  echo The mapper returned an error. Try Run as administrator and review QUICKSTART.txt.
  pause
)

endlocal
