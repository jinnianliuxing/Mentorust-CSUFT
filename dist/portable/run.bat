@echo off
setlocal EnableExtensions
chcp 65001 >nul
title Mentorust - Portable Launcher
cd /d "%~dp0"

echo.
echo   ==================================================
echo      Mentorust  -  Campus Network Client  (Portable)
echo   ==================================================
echo.

if not exist "%~dp0mentorust.exe" goto NOEXE

call :CHECK_NPCAP
if "%NPCAP_OK%"=="1" goto RUN

echo   [!] Npcap is NOT installed on this PC.
echo       Npcap is the packet capture driver Mentorust needs.
echo.

if exist "%~dp0npcap-1.88.exe" goto INSTALL_LOCAL

echo   This package does NOT include an Npcap installer
echo   (Npcap free edition may not be redistributed).
echo.
echo   Opening the official Npcap download page ...
echo.
echo       https://npcap.com/#download
echo.
echo   During Npcap setup, please TICK this option:
echo       [v] Install Npcap in WinPcap API-compatible Mode
echo.
start "" "https://npcap.com/#download"
echo   Press any key AFTER Npcap is installed ...
pause >nul
call :CHECK_NPCAP
if "%NPCAP_OK%"=="1" goto RUN
echo.
echo   [X] Npcap still not detected. Cannot continue.
echo       Install it manually, then run this file again.
echo.
pause >nul
exit /b 1

:INSTALL_LOCAL
echo   Bundled installer found : npcap-1.88.exe
echo   Running it now - please accept the UAC prompt.
echo.
echo   During Npcap setup, please TICK this option:
echo       [v] Install Npcap in WinPcap API-compatible Mode
echo.
pause
set "MENTORUST_NPCAP=%~dp0npcap-1.88.exe"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=$env:MENTORUST_NPCAP; Start-Process -FilePath $p -Verb RunAs -Wait"
call :CHECK_NPCAP
if "%NPCAP_OK%"=="1" goto RUN
echo.
echo   [X] Npcap still not detected.
echo       Please install it manually by double-clicking:
echo           npcap-1.88.exe
echo.
pause >nul
exit /b 1

:RUN
echo   Starting Mentorust ...
start "" "%~dp0mentorust.exe"
exit /b 0

:NOEXE
echo   [ERROR] mentorust.exe was not found in this folder.
echo   Please extract ALL files from the zip first,
echo   then run this file again from the extracted folder.
echo.
pause >nul
exit /b 1

:CHECK_NPCAP
set "NPCAP_OK=0"
if exist "%SystemRoot%\System32\Npcap\Packet.dll" set "NPCAP_OK=1"
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" set "NPCAP_OK=1"
if exist "%SystemRoot%\System32\Packet.dll"  set "NPCAP_OK=1"
if exist "%SystemRoot%\System32\wpcap.dll"   set "NPCAP_OK=1"
exit /b 0
