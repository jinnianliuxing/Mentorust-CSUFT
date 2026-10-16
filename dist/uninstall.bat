@echo off
chcp 65001 >nul
title Mentorust Uninstaller
setlocal EnableExtensions

set "DEST=%LOCALAPPDATA%\Mentorust"
set "LNK=%USERPROFILE%\Desktop\Mentorust.lnk"

echo.
echo   ================================================
echo      Mentorust  -  Uninstaller
echo   ================================================
echo.
echo   Will remove:
echo     - install folder   : %DEST%
echo     - desktop shortcut : Mentorust
echo     - autostart entry  : registry Run key (if present)
echo.
echo   Note: your extracted source folder is NOT touched.
echo.
echo   Type Y and press Enter to confirm (just Enter = cancel):
set "CONFIRM="
set /p CONFIRM=
if not defined CONFIRM goto CANCEL
if /i not "%CONFIRM%"=="Y" goto CANCEL

if not defined LOCALAPPDATA goto BADDEST
if /i not "%DEST%"=="%LOCALAPPDATA%\Mentorust" goto BADDEST

echo.
echo   Stopping Mentorust ...
taskkill /F /IM mentorust.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul

echo   Removing autostart entry ...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Mentorust /f >nul 2>&1

echo   Removing desktop shortcut ...
if exist "%LNK%" del /f /q "%LNK%" >nul 2>&1

echo   Removing install folder ...
if exist "%DEST%" rd /s /q "%DEST%" >nul 2>&1

echo.
echo   ================================================
echo      Uninstall complete
echo   ================================================
echo.
echo   Press any key to exit ...
pause >nul
exit /b 0

:CANCEL
echo.
echo   Cancelled. Nothing was changed.
echo.
pause >nul
exit /b 0

:BADDEST
echo.
echo   [ERROR] Install path looks wrong - deleted nothing to be safe.
echo   Path: %DEST%
echo   Please check and remove it manually.
echo.
pause >nul
exit /b 1
