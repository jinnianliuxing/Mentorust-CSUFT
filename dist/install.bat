@echo off
chcp 65001 >nul
title Mentorust Installer
setlocal EnableExtensions

set "SRC=%~dp0"
set "DEST=%LOCALAPPDATA%\Mentorust"

echo.
echo   ================================================
echo      Mentorust  -  Campus Network Client  Installer
echo   ================================================
echo.

if not exist "%SRC%mentorust.exe" goto NOEXE

echo   Install location: %DEST%
echo.
if not exist "%DEST%" mkdir "%DEST%" >nul 2>&1
if not exist "%DEST%" goto NODIR

echo   [1/3] Copying program ...
copy /y "%SRC%mentorust.exe" "%DEST%\mentorust.exe" >nul
if errorlevel 1 goto COPYFAIL
if not exist "%DEST%\mentorust.exe" goto COPYFAIL
echo         done

echo   [2/3] Creating desktop shortcut ...
set "MENTORUST_DEST=%DEST%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=$env:MENTORUST_DEST; $s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Desktop')+'\Mentorust.lnk'); $s.TargetPath=(Join-Path $d 'mentorust.exe'); $s.WorkingDirectory=$d; $s.Description='Mentorust Campus Auth'; $s.Save()" >nul 2>&1
if errorlevel 1 goto LNKFAIL
echo         done

echo   [3/3] Saving install path ...
echo %DEST% > "%DEST%\install_path.txt"
echo         done

echo.
echo   ================================================
echo      Installation complete
echo   ================================================
echo.
echo   Install location : %DEST%
echo   Desktop shortcut : Mentorust
echo.
echo   How to use:
echo     1. Double-click the "Mentorust" icon on your desktop
echo     2. Enter your campus account and password
echo     3. Choose the wired network card, then click Connect
echo.
echo   IMPORTANT - install Npcap first (packet capture driver):
echo     https://npcap.com/#download
echo     During Npcap setup, check this option:
echo       [v] Install Npcap in WinPcap API-compatible Mode
echo.
echo   Chinese instructions : open README.txt
echo   To uninstall         : run uninstall.bat
echo.
echo   Press any key to exit ...
pause >nul
exit /b 0

:NOEXE
echo   [ERROR] mentorust.exe not found.
echo   Please extract the WHOLE zip to a local folder first,
echo   then run this installer again from that folder.
echo.
pause >nul
exit /b 1

:NODIR
echo   [ERROR] Cannot create install folder: %DEST%
echo   Please check disk space and permissions, then retry.
echo.
pause >nul
exit /b 1

:COPYFAIL
echo   [ERROR] Failed to copy the program file.
echo   Please make sure mentorust.exe is not locked by antivirus software,
echo   then run this installer again.
echo.
pause >nul
exit /b 1

:LNKFAIL
echo         [WARN] Could not create the desktop shortcut. Not critical.
echo         You can still run: %DEST%\mentorust.exe
echo.
echo   ================================================
echo      Installation complete (no shortcut)
echo   ================================================
echo.
echo   Install location : %DEST%
echo.
echo   Press any key to exit ...
pause >nul
exit /b 0
